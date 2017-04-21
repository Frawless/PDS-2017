#################################################
#	Projekt: Projekt do předmětu PDS	#
#		 MitM attack			#
#	 Autoři: Bc. Jakub Stejskal <xstejs24>	#
# Nazev souboru: Makefile			#
#	  Datum: 13. 2. 2017		    	#		
#	  Verze: 1.0				#
#################################################

CC = g++
CFLAGS = -std=c++98 -Wall -pedantic -W -Wextra -O2 -g
LOGIN = xstejs24
FILES = pds-library.o tree.o pds-intercept pds-spoof pds-scanner 
PACK = *.c *.h Makefile dokumentace.pdf

%.o: %.cpp %.h
	$(CC) $(CFLAGS) -c -o $@ $< -I/usr/include/libxml2 -lxml2

all : pds-scanner pds-spoof pds-intercept

pds-scanner: pds-scanner.cpp types.h pds-library.o tree.o
	$(CC) $(CFLAGS) -o $@ pds-scanner.cpp -I/usr/include/libxml2 -lxml2 pds-library.o tree.o -lpcap
	
pds-spoof: pds-spoof.cpp types.h pds-library.o
	$(CC) $(CFLAGS) -o $@ pds-spoof.cpp -lpcap -I/usr/include/libxml2 -lxml2 pds-library.o tree.o   

pds-intercept: pds-intercept.cpp types.h pds-library.o tree.o
	$(CC) $(CFLAGS) -o $@ pds-intercept.cpp -lpcap -I/usr/include/libxml2 -lxml2 pds-library.o tree.o   

	
pack: clean
	rm -f $(LOGIN).zip
	zip -r $(LOGIN).zip $(PACK)
	
	
clean:
	rm -f *.o *.out $(FILES)
