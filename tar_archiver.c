#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
void umple(FILE* f, int val, int cat) //fill command
{
    int i;
    for (i = 0; i < cat; ++i)
    {
        fputc(val, f);
    }
}
union record {
        char charptr[512];
        struct header {
                char name[100];
                char mode[8];
                char uid[8];
                char gid[8];
                char size[12];
                char mtime[12];
                char chksum[8];
                char typeflag;
                char linkname[100];
                char magic[8];
                char uname[32];
                char gname[32];
                char devmajor[8];
                char devminor[8];
        } header;
};
int load_archive(char archiveName[])
{
    union record buffer;
    struct tm t;
    FILE *arhiva, *sursa, *file_ls, *usermap;
    long long checksum, timp, i, cat, dim, permis, j, put;
    unsigned char *r;
    char linie1[512], linie2[512], aux[512], aux2[512], magic[]={"GNUtar "}, *p, *q;


    if((file_ls = fopen("file_ls", "rt")) == NULL)
    {
        fprintf(stderr, "File file_ls can't be open!\n");
        return -1;
    }
    if((usermap = fopen("usermap.txt", "rt")) == NULL)
    {
        fprintf(stderr, "File usermap.txt can't be open!\n");
        return -2;
    }
    if((arhiva = fopen(archiveName, "wb")) == NULL)
    {
        fprintf(stderr, "Archive file can't be open!\n");
        return -3;
    }
    while(fgets(linie1, 512, file_ls))
    {
        memset(&buffer, 0, sizeof(buffer));
        p = strtok(linie1, " "); //the permissions
        permis = 0;
        for(j = 0; j < 3; ++j)
        {
            permis *= 10;
            put = 4;
            for(i = 0; i < 3; ++i)
            {
                if(p[1 + j * 3 + i] != '-') permis += put;
                put /= 2;
            }
        }
        sprintf(buffer.header.mode, "%07d", permis);
        p = strtok(NULL, " "); //number of links
        p = strtok(NULL, " "); //user
        sprintf(buffer.header.uname, "%s", p);
        p = strtok(NULL, " "); //group
        sprintf(buffer.header.gname, "%s", p);
        p = strtok(NULL, " "); //size
        sprintf(buffer.header.size, "%011o", atoi(p));
        p = strtok(NULL, " "); //data
            strcpy(aux2, linie1 + (p - linie1)); //I save it here for later formatting 
        p = strtok(NULL, " "); //hour
            strncpy(aux, p, strchr(p, '.') - p);
        p = strtok(NULL, " "); //+2000
        p = strtok(NULL, " "); //name
        snprintf(buffer.header.name, strlen(p), "%s", p);
        //the time start
        q = strtok(aux2, "-");
        t.tm_year = atoi(q) - 1900;
        q = strtok(NULL, "-");
        t.tm_mon = atoi(q) - 1;
        q = strtok(NULL, "-");
        t.tm_mday = atoi(q);
        q = strtok(aux, ":");
        t.tm_hour = atoi(q);
        q = strtok(NULL, ":");
        t.tm_min = atoi(q);
        q = strtok(NULL, ":");
        t.tm_sec = (q[0] - '0') * 10 + q[1] - '0';
        t.tm_isdst = -1;
        timp = (int)mktime(&t);
        sprintf(buffer.header.mtime, "%011o", timp);
        //the time stop
        fseek(usermap, 0, SEEK_SET);
        while(fgets(linie2, 512, usermap)) //I search through usermap.txt for the user associated with the file
        {
            p = strstr(linie2, buffer.header.uname);
            if(p != NULL)
            {
                p = strtok(linie2, ":"); //username
                p = strtok(NULL, ":"); //(x)
                p = strtok(NULL, ":"); //UID
                snprintf(buffer.header.uid, 8, "%07o", atoi(p));
                p = strtok(NULL, ":"); //GID
                snprintf(buffer.header.gid, 8, "%07o", atoi(p));
                break;
            }
        }
        sprintf(buffer.header.magic, "GNUtar ");
        buffer.header.typeflag = '0';
        sprintf(buffer.header.chksum, "       ");
        r = (unsigned char*)&buffer.header;
        checksum = 4 * 8;
        for(i = 0; i < sizeof(buffer.header); ++i)
        {
            checksum += (int)r[i];
        }
        sprintf(buffer.header.chksum, "%06o", checksum);

        fwrite(&buffer.header, sizeof(buffer.header), 1, arhiva); //writing the header in the archive
        umple(arhiva, 0, 512 - sizeof(buffer.header)); //fill with zeros the rest of the 512 bytes block 
        fseek(arhiva, 0, SEEK_END);

        sursa = fopen(buffer.header.name, "rb");
        fseek(sursa, 0, SEEK_END);
        dim = ftell(sursa);
        fseek(sursa, 0, SEEK_SET);
        for(i = 0; i < dim / 512; ++i) //transfer from the sourche file to the archive 512 bytes at a time
        {
            fread(&buffer.charptr, 512, 1, sursa);
            fwrite(&buffer.charptr, 512, 1, arhiva);
        }
        if(dim % 512 != 0) //transfer the remainder, if the sourche file doesn't have a multiple of 512 of bytes
        {
            fread(&buffer.charptr, dim % 512, 1, sursa);
            fwrite(&buffer.charptr, dim % 512, 1, arhiva);
        }
        if(ftell(arhiva) % 512 != 0) //fill with zeros until I reach a multiple of 512 of bytes
        {
            cat = 512 - (ftell(arhiva) % 512);
            umple(arhiva, 0, cat);
        }
        fseek(arhiva, 0, SEEK_END);
        fclose(sursa);
    }
    umple(arhiva, 0, 1024);
    fseek(arhiva, 0, SEEK_END);
    fclose(arhiva);
    return 0;
}
int list_archive(char archiveName[])
{
    union record buffer;
    int put, i;
    long long dim, octal;
    FILE *arhiva;
    if((arhiva = fopen(archiveName, "rb")) == NULL)
    {
        fprintf(stderr, "Archive file could not be open for listing!\n"); 
        return -5;
    }
    while(fread(&buffer.header, sizeof(buffer.header), 1, arhiva) && strlen(buffer.header.name) > 0) //while I'm able to read headers
    {
        printf("%s\n", buffer.header.name);
        octal = 0;
        for(i = 0; i < 11; ++i)
        {
            octal = octal * 10 + (buffer.header.size[i] - '0');
        }
        put = 1;
        dim = 0;
        while(octal > 0)
        {
            dim += (octal % 10) * put;
            put = put * 8;
            octal = octal / 10;
        }
	//if the size of the file is not divisible by 512, that means that the file was filled to a multiple of 512
        if(dim % 512 != 0)
        {
            dim = (dim / 512 + 1) * 512;
        }
        dim += 512 - sizeof(buffer.header);
        fseek(arhiva, dim, SEEK_CUR);
    }
    fclose(arhiva);
    return 0;
}
int get_file(char archiveName[], char fileName[])
{
    FILE *arhiva, *testam;
    union record buffer;
    long long octal, dim, put;
    int i;

    if((arhiva = fopen(archiveName, "rb")) == NULL)
    {
        fprintf(stderr, "Archive file could not be open!\n"); 
        return -6;
    }
    while(fread(&buffer, 512, 1, arhiva))
    {
        if(strcmp(buffer.header.name, fileName) == 0)
        {
            testam = fopen("testamImg", "wb"); //test file
            octal = 0;
            for(i = 0; i < 11; ++i) //remember the size in octal with an int
            {
                octal = octal * 10 + (buffer.header.size[i] - '0');
            }
            put = 1;
            dim = 0;
            while(octal > 0) //transform the size in decimal
            {
                dim += (octal % 10) * put;
                put = put * 8;
                octal = octal / 10;
            }
            for(i = 0; i < dim / 512; ++i)
            {
                fread(&buffer.charptr, 512, 1, arhiva);
                fwrite(&buffer.charptr, 512, 1, stdout);
                fwrite(&buffer.charptr, 512, 1, testam);
            }
            if(dim % 512 != 0)
            {
                fread(&buffer.charptr, dim % 512, 1, arhiva);
                fwrite(&buffer.charptr, dim % 512, 1, stdout);
                fwrite(&buffer.charptr, dim % 512, 1, testam);
            }
            fclose(arhiva);
            fclose(testam);
            return 0;
        }
    }
    fclose(arhiva);
    return -7;
}
int main()
{
    char input[512], archiveName[512], fileName[512];
    while(scanf("%s", input) && strcmp(input, "quit") != 0)
    {
        if(strcmp(input, "load") == 0)
        {
            scanf("%s", archiveName);
            load_archive(archiveName);
        }
        else if(strcmp(input, "list") == 0)
        {
            scanf("%s", archiveName);
            list_archive(archiveName);
        }
        else if(strcmp(input, "get") == 0)
        {
            scanf("%s", archiveName);
            scanf("%s", fileName);
            get_file(archiveName, fileName);
        }
    }
    return 0;
}

