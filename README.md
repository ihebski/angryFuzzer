# AngryFuzz3r
![screen_1](http://i.imgur.com/QetqbO1.png)

Status: **Development**
## About the AngryFuzz3r project
AngryFuzz3r is a collection of tools for pentesting to gather information and discover vulnerabilities of the targets based on Fuzzedb https://github.com/fuzzdb-project/fuzzdb project
## UrlFuzz3r->AngryFuzz3r_1
Discover hidden files and directories on a web server. The application tries to find url relative paths of the given website by comparing them with a given set .

## Features

* Fuzz url set from an input file
* Concurrent relative path search
* Configurable number of fuzzing workers
* Fuzz CMS ==> Wordpress,Durpal,Joomla
* Generate reports of the valid paths
## Usage

~~~
$ python angryFuzzer.py -h
Usage: angryFuzzer.py [options]

Options:
  -h, --help            show this help message and exit
  -q, --quiet           Silent mode ,only reports
  -u URL, --url=URL      URL of the Target
  -c CMS, --cms=CMS     scan CMS ==> wp ,dp
  -w WORDLIST, --wordlist=WORDLIST
                        Custom wordlist

~~~

Example:
* Fuzzing an url with default dictionary
~~~
python angryFuzzer.py -u http://127.0.0.1 
~~~

* Fuzzing CMS (wp: in this exemple !)
~~~
python angryFuzzer.py -u http://127.0.0.1 --cms wp 
~~~

* Fuzzing a custom Wordlist
~~~
python angryFuzzer.py -u http://127.0.0.1 -w fuzzdb/discovery/predictable-filepaths/php/PHP.txt
~~~
![screen_2](http://i.imgur.com/0C4Lb42.png)



## How to install
##### Clone
 - Clone the repository with:
```sh
$ git clone https://github.com/ihebski/angryFuzzer.git
$ cd angryFuzzer
$ python angryFuzzer.py
```
##### Dependencies
* Install the required dependencies with:
```bash
$ sudo pip install -r requirements.txt
```
## License
The MIT License (MIT)
