#################################################
#	Projekt: Projekt do předmětu PDS	#
#		 MitM attack			#
#	 Autoři: Bc. Jakub Stejskal <xstejs24>	#
# Nazev souboru: Makefile			#
#	  Datum: 13. 2. 2017		    	#		
#	  Verze: 1.0				#
#################################################

CC = gcc 
CFLAGS = -std=gnu99 -Wall -pedantic -W -Wextra
LOGIN = xstejs24
FILES = pds-intercept pds-spoof pds-scanner
PACK = *.c *.h Makefile dokumentace.pdf

all : pds-intercept pds-spoof pds-scanner

pds-scanner: pds-scanner.c
	$(CC) $(CFLAGS) -o $@ pds-scanner.c
	
pds-spoof: pds-spoof.c
	$(CC) $(CFLAGS) -o $@ pds-spoof.c
	
pds-intercept: pds-intercept.c
	$(CC) $(CFLAGS) -o $@ pds-intercept.c
	
pack: clean
	rm -f $(LOGIN).zip
	zip -r $(LOGIN).zip $(PACK)
	
	
clean:
	rm -f *.o *.out $(FILES)
