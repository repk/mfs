CC=gcc
CFLAGS=-Wextra -Wall -DDEBUG
LDFLAGS=
BUILDDIR?=build
OBJDIR=$(BUILDDIR)/tools
EXEC=mount.mfs
SRC= mount.mfs.c
OBJ= $(SRC:.c=.o)
DEPS = $(OBJ:.o=.d)

all: $(OBJDIR)/$(EXEC)

$(OBJDIR)/$(EXEC): $(OBJDIR)/$(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) -o $@ -c $< $(CFLAGS) -MMD

$(OBJDIR):
	mkdir -p $(OBJDIR)

.PHONY: clean mrproper

clean:
	rm -rf $(OBJDIR)/*.o
	rm -rf $(OBJDIR)/*.d

mrproper: clean
	rm -rf $(OBJDIR)

-include $(OBJDIR)/$(DEPS)
