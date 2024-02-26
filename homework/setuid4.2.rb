#!/usr/bin/ruby
 
aFile = File.new("flag", "r")
if aFile
   content = aFile.sysread(100)
   puts content
else
   puts "Unable to open file!"
end