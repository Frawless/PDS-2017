#################################################
#	Projekt: Projekt do předmětu PDS	#
#		 MitM attack			#
#	 Autoři: Bc. Jakub Stejskal <xstejs24>	#
# Nazev souboru: Makefile			#
#	  Datum: 13. 2. 2017		    	#		
#	  Verze: 1.0				#
#################################################

CC = g++
CFLAGS = -std=c++98 -Wall -pedantic -W -Wextra -O2
LOGIN = xstejs24
FILES = pds-library.o pds-intercept pds-spoof pds-scanner 
PACK = *.c *.h Makefile dokumentace.pdf

%.o: %.cpp %.h
	$(CC) $(CFLAGS) -c -o $@ $<

all : pds-intercept pds-spoof pds-scanner

pds-scanner: pds-scanner.o pds-library.o
	$(CC) $(CFLAGS) -o $@ pds-scanner.o pds-library.o -lpcap
	
pds-spoof: pds-spoof.o pds-library.o
	$(CC) $(CFLAGS) -o $@ pds-spoof.o pds-library.o -lpcap 
	
pds-intercept: pds-intercept.o pds-library.o
	$(CC) $(CFLAGS) -o $@ pds-intercept.o pds-library.o -lpcap

	
pack: clean
	rm -f $(LOGIN).zip
	zip -r $(LOGIN).zip $(PACK)
	
	
clean:
	rm -f *.o *.out $(FILES)
