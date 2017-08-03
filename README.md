Tarball archiver implemented in C.

The program receives commands from standard input and uses two aditional file: usermap.txt and file_ls.
file_ls contains information about the files to be archived and usermap.txt contains information about the users in the system.
Every command is represented by a line.

Commands may be:

	load archivename: create the archive using information from usermap.txt and file_ls with the name archivename
	
	list archivename: list the files contained by archivename
	
	get archivename filename: extract the filename file from the archivename archive and display it at stdout
	
		usage ex: echo -e “get archive file.jpg\nquit” | ./my_tar > result.jpg
	
	
