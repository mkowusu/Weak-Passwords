/*
 * Network Security
 * Programming exercise: Checking for weak 
 * passwords
 * 02/03/15
 *
 * Ethan Ratliff-Crain - Box: 4353
 * Michael Owusu       - Box: 4271
 *
 * Used resources provided by Dr. John Stone
 * http://courses.homelinux.org/security/password-checker.html
 * 
 *
 * For help with reading and writing files in our program
 * http://www.tutorialspoint.com/cprogramming/c_file_io.htm
 *
 */

#define _XOPEN_SOURCE
#include<stdio.h>
#include<string.h>
#include<unistd.h>

int main()
{
  // Declarations
  FILE *output;
  char buf[1000];
  char salt[13];
  char encode[100];
  char usr[10];
  char *testcode;
  char key[80];
  char testpass[100];
  FILE *pass_file;
  FILE *test_file;
  int len;

  // Open file containing passwords to be decrypted
  pass_file =fopen("passwd.txt","r");
  if (!pass_file)
    return 1;
  
  // initiate file that will store exposed passwords
  output =fopen("found_pwds.txt","w");
  if (!output)
    return 1;
  
  // Begin reading file of encrypted passwords
  while (fgets(buf,1000, pass_file)!=NULL){

    // Parsing of encrypted passwords
    salt[0]='$';
    salt[1]='6';
    salt[2]='$';
    salt[3]=NULL;
    strcpy(usr, strtok(buf, "$"));
    strtok(NULL, "$");
    strcat(salt, strtok(NULL, "$"));
    strcat(salt, "$");
    strcpy(encode, salt);
    strcat(encode, strtok(NULL, ":"));

    // open file of common passwords to use as guesses
    test_file =fopen("top2000.txt","r");
    if (!test_file)
      return 1;

    // run crypt on parsed encrypted password using parsed salt
    while (fgets(testpass,100, test_file)!=NULL){
      len = strlen(testpass);
      testpass[len-1]='\0';
      testcode = crypt(testpass, salt); 

      // If successfully decrypted, print username and password
      if (strcmp(testcode, encode)==0)
        fprintf(output, "%s %s\n", usr, testpass);
    }

    // Finish up
    fclose(test_file);
  }
  fclose(pass_file);
  return 0;
}

