# Windows 10 and Files (e-mail)

From the Windows 10 Scenario, the first paragraph mentions that there should be no non-work related files or hacking tools on the computer.  What constitutes non-work related files or hacking tools.

## Non-work Related Files

So, what is a work related file.  This tends to be directed by the type of work the person using the computer is doing.  If you do not have that information, it generally relates to stuff that the person would have on the computer that is personal.  In general, pictures, music, and games.  Most places of employment may not be strict on the rule, but in general do not want your family history in pictures clogging up the resources that they pay for.  Or have your entire iTunes library saved on your local computer.  Or have all of the memes that you've downloaded from your social media stored for quick retrieval.  There are exceptions to the rules, such as historians, musicians, and Meme-ologists, but those are the edge cases.

And how do you find these non-work related files? This tends to be more of a search and remove operation, and can be quite manual.  The most popular method will be finding the files by the file extension, which is loosely the file type.  Once you find files of the certain extension, you make a call on if they sound like they are work related or not.  Popular extensions include:

- Music: .mp3, .mp4, .m4a, .wav,...
- Pictures and images: .jpg, .jpeg, .gif, .png, .bmp, .tif, .tiff,...

The list of extensions is by no means complete.  But can give you a good start of where to look.  It may be a good idea of using your favorite search engine and search for `extensions of music files`.

When you find files, many times you will see what folder, or directory, they exist in, which can also give you another place to look.  If you find a `.mp3` stored in a folder called `jokes`, you can assume there will be more non-work related files in there.  Unless the user is a Joke-ologist.

## How to Find Files

Obviously, searching for `how to find music files on my computer` can be a good start, and can give you some ideas.

To find files on a Windows system, it is generally as easy as pulling up the File Explorer, finding the C:\, and then typing a file extension with a wild card into the search bar.  Example of searching for Music files would be typing `*.mp3` in the search bar and wait for the results.  Then repeat with with `*.mp4`, and `*.wav`, and so on.  Each find can take a long time, but is the quickest and easiest way to search.  Another option may be to use the Search button bar to select the Kind of file to search for, such as `kind:=music`.

If you are more programatic, and like to run commands to find files, Windows has a powerful scripting language called Powershell that can be used.  To search for all `.mp3` and `.jpg` on the `C:\`, you would open the Powershell prompt and type:

```
cd c:\
Get-Childitem –Path C:\ -Include *.mp3,*.jpg -Recurse -ErrorAction SilentlyContinue | Foreach { $_.FullName }
```

With those commands, you should now have a list of every file on the drive that ends with `.mp3` or `.jpg`, along with the full path to the file.

## Hacking Tools

Hacking tools tend to be tools that can be used for the subversion of policies and rules on the system or network.  It is hard to classify what a hacking tool is by name, so this may take a bit more work.  Some common hacking tools are called MetaSploit, NetCat, WireShark, PowershellEmpire, ...

In general, there are 2 things that you will have to do to find Hacking tools.  

The first method is to look at all of the programs that are installed on the computer, and identify if they are meant for business or not.  This becomes an exercise in searching for the program description on the internet to find out what it does, and then make a decision on if it is meant for buisness or not.  Windows can be good as it has a central registry of what was installed onto the computer.  You can go to `Control Panel->Programs->Uninstall a Program` and see a list of all applications that were installed onto the computer.  There you can then search the name of the program and determine if it should be uninstalled.

But, if I'm a "hacker", and want to install a program on a computer, I will do what ever I can to not have the program register in the central registry.  In that case, you will have to return to the finding of files of type of `kind:=program` or search for files of the extension `.exe`.  Unfortunately, those may come up with very large lists of valid files, and thus may not be feasible.  A good start would be to look in C:\, and C:\Program Files for folder names that do not look "correct".

