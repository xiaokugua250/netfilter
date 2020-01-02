netfiler:
	gcc src/netfilter.c -lnfnetlink -lnetfilter_queue -lmnl -o bin/netfiler
clean:
	rm -rf bin/*
 
