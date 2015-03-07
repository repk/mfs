#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>

#include <sys/mount.h>

#define MOUNT_FLAGS (MS_NOSUID | MS_NODEV)

#define PASSLEN 256
#define LOGINLEN 1024

struct mount_opt {
	char *source;
	char *target;
	char *bufopt;
	size_t bufopt_len;
	size_t bufopt_size;
	unsigned long mountflags;
	uint32_t login : 1,
		 pass : 1;
};

#define ROUNDUP(a, n) ((((a) - 1) / (n)) * (n) + 1)

#define MOUNT_OPT_BUFLEN 256


static inline void usage(char const *prog)
{
	(void)prog;
	fprintf(stderr, "Error usage\n");
	exit(-1);
}

static inline int mount_opt_init(struct mount_opt *opt)
{
	char *bufopt;
	bufopt = malloc(MOUNT_OPT_BUFLEN * sizeof(*bufopt));
	if(bufopt == NULL)
		return -ENOMEM;
	bufopt[0] = '\0';

	opt->source = NULL;
	opt->target = NULL;
	opt->bufopt = bufopt;
	opt->bufopt_len = 0;
	opt->bufopt_size = MOUNT_OPT_BUFLEN;
	opt->mountflags = MOUNT_FLAGS;
	opt->login = 0;
	opt->pass = 0;

	return 0;
}

static inline int mount_opt_exit(struct mount_opt *opt)
{
	free(opt->bufopt);
	return 0;
}

static inline int mount_opt_add_option(struct mount_opt *opt, char const *str)
{
	size_t len = strlen(str) + 1;
	char *p;

	if(opt->bufopt_len != 0 && str[0] != ',')
		++len;

	if(opt->bufopt_len + len >= opt->bufopt_size) {
		p = realloc(opt->bufopt, ROUNDUP(opt->bufopt_len + len,
					MOUNT_OPT_BUFLEN));
		if(p == NULL)
			return -ENOMEM;

		opt->bufopt = p;
		opt->bufopt_size = ROUNDUP(opt->bufopt_len + len,
				MOUNT_OPT_BUFLEN);
	}

	if(opt->bufopt_len != 0 && str[0] != ',')
		strcat(opt->bufopt, ",");

	strcat(opt->bufopt, str);
	opt->bufopt_len += len;
	return 0;
}

static ssize_t passwd(int fd, char *pass, size_t len)
{
	struct termios fl, savefl;
	ssize_t ret;

	if(tcgetattr(fd, &fl) < 0)
		goto err;

	savefl = fl;
	fl.c_lflag &= ~ECHO;

	if(tcsetattr(fd, TCSANOW, &fl) < 0)
		goto err;

	printf("Password: ");
	fflush(stdout);

	ret = read(fd, pass, len);
	if(ret < 0 || pass[ret - 1] != '\n')
		goto err;

	pass[ret - 1] = '\0';
	--ret;

	fl = savefl;
	tcsetattr(fd, TCSAFLUSH, &fl);

	printf("\n");

	return ret;
err:
	perror("Cannot get password");
	return -1;
}

static ssize_t login(int fd, char *login, size_t len)
{
	ssize_t ret;

	printf("Login: ");
	fflush(stdout);

	ret = read(fd, login, len);
	if(ret < 0 || login[ret - 1] != '\n')
		goto err;

	login[ret - 1] = '\0';
	--ret;

	return ret;
err:
	perror("Cannot get login");
	return -1;
}

static int parse_mnt_opt(struct mount_opt *opt, char const *str)
{
	if(strstr(str, "login=") != NULL)
		opt->login = 1;
	if(strstr(str, "pass=") != NULL)
		opt->pass = 1;

	return mount_opt_add_option(opt, str);
}

static int parse_opt(struct mount_opt *opt, int argc, char **argv)
{
	int i, ret = 0;

	for(i = 0; i < argc; ++i)
		printf("%s ", argv[i]);
	printf("\n");

	if(argc < 3)
		usage(argv[0]);

	for(i = 1; i < argc; ++i) {
		if(strcmp(argv[i], "-o") == 0) {
			++i;
			if(i == argc)
				break;
			ret = parse_mnt_opt(opt, argv[i]);
			if(ret != 0)
				break;
		} else if(argv[i][0] != '-' && (opt->source == NULL)) {
			opt->source = argv[i];
		} else if(argv[i][0] != '-' && (opt->target == NULL)) {
			opt->target = argv[i];
		} else {
			fprintf(stderr, "%s invalid argument\n", argv[i]);
			usage(argv[0]);
		}
	}


	return ret;
}


int main(int argc, char **argv)
{
	struct mount_opt opt;
	char l[LOGINLEN], pass[PASSLEN];
	char passopt[PASSLEN + sizeof("pass=") - 1];
	char lopt[LOGINLEN + sizeof("login=") - 1];
	int ret;

	ret = mount_opt_init(&opt);
	if(ret != 0)
		goto out;

	ret = parse_opt(&opt, argc, argv);
	if(ret != 0)
		goto optclean;

	if(opt.login == 0) {
		login(STDIN_FILENO, l, PASSLEN);
		opt.login = 1;
		sprintf(lopt, "login=%s", l);
		mount_opt_add_option(&opt,lopt);
	}

	if(opt.pass == 0) {
		passwd(STDIN_FILENO, pass, PASSLEN);
		opt.pass = 1;
		sprintf(passopt, "pass=%s", pass);
		mount_opt_add_option(&opt, passopt);
	}

	ret = mount(opt.source, opt.target, "mfs", opt.mountflags,
			opt.bufopt);

	if(ret < 0) {
		perror("Mount fail (maybe see dmesg for further info)");
	}

optclean:
	mount_opt_exit(&opt);
out:
	return ret;
}
