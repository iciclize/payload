OBJS=main.o netutil.o ip2mac.o sendBuf.o napt.o routes.o params.o ip.o yjsnpi.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall -DYJSNPI_DEBUG
LDLIBS=-lpthread
TARGET=router
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

clean:
	/bin/rm *.o
