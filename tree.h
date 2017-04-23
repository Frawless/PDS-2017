/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   tree.h
 * Author: frawless
 *
 * Created on 12. dubna 2017, 21:51
 */
//inkludované knihovny
#include <ctype.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <netinet/ip6.h>
#include <netinet/if_ether.h>

#include <iostream>
#include <fstream>
#include <sstream>

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "types.h"

#ifndef TREE_H
#define TREE_H


/**
 * Funkce pro inicializaci stromu.
 * @param root ukaaztel strom
 */
void treeInit(T_NODE_PTR* root);

/**
 * Funkce pro vkládání nalezených IPv4 adres do stromu. Díky funkci stromu je eliminována možnost duplictních výskytů adres.
 * @param root - ukazatel nastrom
 * @param macAddr - vkládající MAC
 * @param ipv4 - vkládající IPv4
 */
void insert(T_NODE_PTR* root,u_char* macAddr, u_char* ipv4);

/**
 * Funkce pro vkládání nalezených IPv6 adres do stromu. Díky funkci stromu je eliminována možnost duplictních výskytů adres.
 * @param root - ukazatel nastrom
 * @param macAddr - vkládající MAC
 * @param ipv6 - vkládající IPv6
 */
void insert(T_NODE_PTR* root,u_char* macAddr, char* ipv6);

/**
 * Funkce pro vypsání stromu do souboru v požadovaném XML formátu. Adresy jsu vypsány pouze pokud jsou uloženy ve stromu.
 * @param root - ukazatel nastrom
 * @param outputFile - výstupní soubor
 */
void printTree(T_NODE_PTR root, std::ofstream& outputFile);

/**
 * Funkce pro smazání stromu z paměti.
 * @param root - ukazatel na strom
 */
void dispose (T_NODE_PTR *root);


#endif /* TREE_H */

