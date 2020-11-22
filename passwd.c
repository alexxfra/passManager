#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

//HEADER CHECKSUM TEXT FEEL FREE TO CHANGE
#define HEADERTEXT "ballin'butatwhatcost"
//MODIFY MAXLEN OF USERNAME/PASSWORD
#define MAXLEN 25

typedef struct Pass{
    char site[MAXLEN];
    char encpass[MAXLEN];
    int passlength;
    struct Pass *next;
}Pass;

int addPass(Pass **table, char *key);
char *encXOR(char *pass, char *key, int passlength);
char *readLn();
char *validateReadLn(int maxlen);
int printTable(Pass **table, char *key);
int printPass(Pass **table, char *key);
void writeFile(Pass **table, char *key, FILE *fp, char *path);
void readFile(Pass **table, FILE *fp,  char *path);
void clearTable(Pass **table);

int main(void){

    char *filename;
    FILE *fp = NULL;
    do
    {
        printf("Please enter path to file: ");
        filename = readLn();
        fp = fopen(filename,"r+b");
        if(fp == NULL)
            printf("Invalid path.\n");
    } while (fp == NULL);
    
    char *key;
    Pass *table = NULL;
    long *fileSize = (long *) malloc(sizeof(long));
    char userOption;

    //Find size of file.
    fseek(fp, 0, SEEK_END);
    *fileSize = ftell(fp);
    
    //If file is empty read new master key and create header. Then continue.
    if (*fileSize == 0){
        printf("File is empty.\nPlease select Master key for XOR encryption: ");
        key = readLn();

        char *encheader = encXOR(HEADERTEXT, key, strlen(HEADERTEXT));
        fwrite(encheader, (strlen(HEADERTEXT)+1) * sizeof(char) , 1, fp);
        free(encheader);
    }
    //If file is smaller than the header size, file is invalid and close program.
    else if (*fileSize < (strlen(HEADERTEXT) + 1)){
       printf("File is invalid. Terminating program.\n");
       return 1;
    }
    //If file is larger or equal to header size, check header. If it matches grant access otherwise terminate program.
    else{
        rewind(fp);
        printf("Please enter master key: ");
        key = readLn();
        char *encheader = (char *) malloc((strlen(HEADERTEXT)+1) * sizeof(char));
        fread(encheader, (strlen(HEADERTEXT)+1) * sizeof(char), 1, fp);
        
        char *header = encXOR(encheader, key, strlen(HEADERTEXT));
        
        if(strncmp(HEADERTEXT, header, strlen(HEADERTEXT)) == 0){
            free(header);
            printf("ACCESS GRANTED.\n");
        }
        else{
            printf("Wrong master key. Terminating program.\n");
            free(header);
            return 1;
        }
    }
    
    //Free unused variable and check the rest of the file for data.
    free(fileSize);
    fclose(fp);
    readFile(&table, fp, filename);

    //Main program loop to let user decide what he wants to do.
    while(1){
        printf("Enter only the number of your selection. Other options are ignored.\nIf you enter a string only the first character will be considered.\n");
        printf("1. Add entry\n2. Print specific password\n3. Print table of passwords\n4. Write password table to file.\n5. Quit\nPlease choose a command: ");
        userOption = getc(stdin);
        while(getc(stdin) != '\n');
        
        switch (userOption)
        {
        case '1':
            printf("\n");
            addPass(&table, key);
            printf("\n");
            break;

        case '2':
            printf("\n");
            printPass(&table, key);
            break;

        case '3':
            printf("\n");
            printTable(&table, key);
            break;

        case '4':
            printf("\nPasswords were saved to file.\n\n");
            writeFile(&table, key, fp, filename);
            break;

        case '5':
            printf("\nTerminating program.\n");
            clearTable(&table);
            free(key);
            free(filename);
            return 0;
            break;
        
        default:
            printf("\nInvalid input.\n");
            break;
        }
               
        
    }
    return 0;
}

//Adds password to the list. If user enters the website which is already inside the list the password is overwritten.
int addPass(Pass **table, char *key){
    char *input;
    char *output;
    Pass *current = (*table);
    Pass *new = (Pass*) malloc(sizeof(Pass));

    
    printf("Enter website name/address(MAX %d characters): ", MAXLEN);
    input = validateReadLn(MAXLEN);

    while(current != NULL){
        if(!strncmp(current->site,input, strlen(input) * sizeof(char))){
            printf("Website is already stored in the table. Password will be overwritten.\n");
            free(input);
            printf("Enter password to save: ");
            input = validateReadLn(MAXLEN);
            current->passlength = strlen(input);
            output = encXOR(input, key, current->passlength);
            memcpy(current->encpass, output, sizeof(current->encpass));
            free(input);
            free(output);
            free(new);
            return 0;
        }
        current = current->next;
    }

    strncpy(new->site, input, sizeof(new->site));
    free(input);
    
    printf("Enter password to save: ");
    input = validateReadLn(MAXLEN);
    new->passlength = strlen(input);
    
    output = encXOR(input, key, new->passlength);
    memcpy(new->encpass, output, sizeof(new->encpass));
    free(input);
    free(output);

    new->next = (*table);
    (*table) = new;
    return 0;
}

//Encrypt string in parameter with XOR returns dynamically allocated string.
char *encXOR(char *pass, char *key, int passlength){
    int keylength = strlen(key);
    char *output = (char *) malloc((passlength+1) * sizeof(char));

    int i;
    for (i = 0; i < passlength; i++){
        output[i] = pass[i] ^ key[i % keylength];
    }
    output[i] = '\0';
    return output;
}

//Read and dynamically allocate a string. Returns pointer to it.
char *readLn(){
    char *line;
    char in = EOF;
    int index = 0;

    line = (char*)malloc(sizeof(char));

    while (in != '\n') {
        in = getc(stdin);

        line = (char*)realloc(line, (index+1) * sizeof(char));

        line[index] = in;
        index++;
    }
    line[index-1] = '\0';

    return line;
}

//Same as readLn but limits the user to a certain string length.
char *validateReadLn(int maxlen){
    char *line;
    int length;
    do{
        line = readLn();
        length = strlen(line);
        if(length > maxlen){
            printf("Enter string with correct length: ");
            free(line);
        }
    }while(length > maxlen);
    
    return line;
}

//Prints the whole list of websites:passwords
int printTable(Pass **table, char *key){
    Pass *current = (*table);
    if(current == NULL){
        printf("There are no passwords in the file. Please add one.\n\n");
        return 1;
    }
    int keylength = strlen(key);
    char *passwordOutput;
    printf("Table of passwords:\n%-*s %-*s\n", MAXLEN, "WEBSITE", MAXLEN, "PASSWORD");
    while(current != NULL){
        passwordOutput = encXOR(current->encpass, key, current->passlength);
        passwordOutput[current->passlength] = '\0';
        printf("%-*s %-*s\n", MAXLEN, current->site, MAXLEN, passwordOutput);
        free(passwordOutput);
        current = current->next;
    }
    printf("\n");
    return 0;
}

//Prints a specific password belonging to a user entered website.
int printPass(Pass **table, char *key){
    Pass *current = (*table);
    if(current == NULL){
        printf("There are no passwords in the file. Please add one.\n\n");
        return 1;
    }
    char *site;
    int keylength = strlen(key);
    char *passwordOutput;

    printf("Enter webiste name: ");
    site = readLn();
   
    while(current != NULL){
        if(!strcmp(current->site, site)){
            passwordOutput = (char *) malloc(current->passlength * sizeof(char));
            passwordOutput = encXOR(current->encpass, key, current->passlength);
            printf("Password: %s\n\n", passwordOutput);
            free(passwordOutput);
            return 0;
        }
        current = current->next;
    }
    printf("Password not found.\n\n");

    return 0;
}

//Writes the data from the list to file.
void writeFile(Pass **table, char *key, FILE *fp, char *path){
    fp = fopen(path, "wb");
    
    char *encheader = encXOR(HEADERTEXT, key, strlen(HEADERTEXT));
    fwrite(encheader, (strlen(HEADERTEXT)+1) * sizeof(char) , 1, fp);
    free(encheader);

    Pass *current = (*table);

    while (current != NULL){
        fwrite(current, sizeof(Pass), 1, fp);
        current = current->next;
    }
    fclose(fp);
}

//Reads password table data from file
void readFile(Pass **table, FILE *fp, char *path){
    clearTable(table);

    //This part calculates the number of Pass structs stored in the file.
    fp = fopen(path, "rb");
    fseek(fp, 0, SEEK_END);
    size_t end = ftell(fp);
    
    fseek(fp, strlen(HEADERTEXT)+1, SEEK_SET);
    size_t start = ftell(fp);
    
    size_t dataSize = end-start;
    Pass *new;

    for (int i = 0; i < dataSize/sizeof(Pass); i++){
        new = (Pass*) malloc(sizeof(Pass));
        fread(new, sizeof(Pass), 1, fp);
        new->next = (*table);
        (*table) = new;
    }
    fclose(fp);
}

//Clears all data from the list
void clearTable(Pass **table){
    Pass *current = (*table);
    Pass *tmp;

    while(current != NULL){
        tmp = current;
        current = current->next;
        free(tmp);
    }
    (*table) = NULL;
}