#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 22 19:31:50 2021

"""
import csv
import pprint

defualt_language = 'English'

FILE = 'Kiwix Library - Kiwix library.csv'
ALL = 'ALL'
keys = ['Title', 'Description', 'Language',
        'Source', 'Flavour', 'URL', '_size']
TITLE = keys[0]
DESCRIPTION = keys[1]
LANGUAGE = keys[2]
SOURCE = keys[3]
FLAVOUR = keys[4]
URL = keys[5]
SIZE = keys[6]


def search(string: str,
           language: str = defualt_language,
           verbose: bool = True) -> list:
    with open(FILE, mode='r') as file:
        csv_file = csv.DictReader(file)
        search_results = []
        for dictionary in csv_file:
            if dictionary[LANGUAGE] == defualt_language:
                concatenated = ''
                for key in dictionary:
                    concatenated += dictionary[key]
                if string.lower() in concatenated.lower():
                    search_results.append(dictionary)
    if verbose:
        sort = {}
        for source in [i[SOURCE] for i in search_results]:
            sort[source] = []
        for result in search_results:
            sort[result[SOURCE]] += [[result[TITLE],
                                     result[DESCRIPTION],
                                     result[FLAVOUR],
                                     result[URL],
                                     '{} gb'.format(
                                         int(result[SIZE])*0.000001)]]
        for key in sort:
            print(
                '------------------- SOURCE: {} ------------------- \n'.format(
                    key))
            for i in sort[key]:
                print(
                    'Title: {}\n'
                    'Description:\n{}\n'
                    'Flavour: {}\n'
                    'URL: {}\n'
                    'Size: {}\n'.format(
                        i[0],
                        i[1],
                        i[2],
                        i[3],
                        i[4]))
        print(200*'-'+'\n')
    return search_results


def get_keys():
    with open(FILE, mode='r') as file:
        csv_file = csv.DictReader(file)
        for dictionary in csv_file:
            return list(dictionary.keys())


def get_sources(Language: str = ALL):
    with open(FILE, mode='r') as file:
        csv_file = csv.DictReader(file)
        sources = {}
        if Language == ALL:
            for dictionary in csv_file:
                source = dictionary[SOURCE]
                language = dictionary[LANGUAGE]
                if source in sources:
                    if language in sources[source]:
                        sources[source][language] += 1
                    else:
                        sources[source] = {language: 1}
                else:
                    sources[source] = {}
                    sources[source][language] = 1
        else:
            for dictionary in csv_file:
                if dictionary[LANGUAGE] == Language:
                    source = dictionary[SOURCE]
                    sources[source] = 1
            lst = list(sources.keys())
            lst.sort()
            sources = lst
    return sources


def get_languages():
    with open(FILE, mode='r') as file:
        csv_file = csv.DictReader(file)
        languages = {}
        for dictionary in csv_file:
            if dictionary[LANGUAGE] in languages:
                dictionary[LANGUAGE] += 1
            else:
                dictionary[LANGUAGE] = 1
    return dictionary


def biggest_of_source(source: str, language: str = ALL):
    with open(FILE, mode='r') as file:
        csv_file = csv.DictReader(file)
        size = 0
        if language == ALL:
            All = {}
            for Language in get_languages():
                All[Language] == biggest_of_source(source, Language)
            return All
        else:
            for dictionary in csv_file:
                if dictionary['Language'] == language and dictionary['Source'] == source:
                    if int(dictionary['_size']) > size:
                        size = int(dictionary['_size'])
                        biggest = dictionary
    return biggest


def main():
    if get_keys() != keys:
        print('This file probably needs updating or changing.')
    print("Here's an example of the 'search' function:\n"
          "running: search('medicine')\ngives:")
    search('medicine')
    print('Column Titles or Dictionary Keys:\n{}'.format(get_keys()))
    print('\n{} Sources:'.format(defualt_language))
    for source in get_sources(defualt_language):
        print(source)
    sources_to_get = [
        'Wikipedia',
        'Wikibooks',
        'Wikiquote',
        'Wiktionary',
        'Wikem'
        ]
    print('\nSources I want:\n{}\n'.format(sources_to_get))
    print('The biggest from these sources:\n')
    list_of_biggest = []
    total_size = 0
    for source in sources_to_get:
        biggest = biggest_of_source(source, defualt_language)
        list_of_biggest.append(biggest)
        total_size += int(biggest[SIZE])
        pprint.pprint(biggest)
        print()
    print("URLs:")
    print([i[URL] for i in list_of_biggest])
    print('\nTOTAL SIZE: {} Gigabytes'.format(total_size*0.000001))



if __name__ == '__main__':
    main()
