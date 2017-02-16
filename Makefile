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
FILES = pds-intercept pds-spoof pds-scanner
PACK = *.c *.h Makefile dokumentace.pdf

all : pds-intercept pds-spoof pds-scanner

pds-scanner: pds-scanner.cpp
	$(CC) $(CFLAGS) -o $@ pds-scanner.cpp
	
pds-spoof: pds-spoof.cpp
	$(CC) $(CFLAGS) -o $@ pds-spoof.cpp
	
pds-intercept: pds-intercept.cpp
	$(CC) $(CFLAGS) -o $@ pds-intercept.cpp
	
pack: clean
	rm -f $(LOGIN).zip
	zip -r $(LOGIN).zip $(PACK)
	
	
clean:
	rm -f *.o *.out $(FILES)
