#!/usr/bin/perl
 
open(DATA, "</flag") or die "/flag文件无法打开, $!";
 
while(<DATA>){
   print "$_";
}