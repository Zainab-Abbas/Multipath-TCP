CC     = g++
OPT    = -Og
CFLAGS = -g
LIBS   = -lpcap -lssl -lcrypto
 
OBJS   = main.o packet.o multipath_connection.o
EXEC   = Multipath

multipath: $(EXEC)

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(EXEC): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

test: multipath
	./$(EXEC) ../file.pcap

clean:
	$(RM) -f $(OBJS) $(EXEC)


