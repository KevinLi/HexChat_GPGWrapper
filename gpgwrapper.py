"""GPG wrapper plugin for HexChat"""

__module_name__ = "GPGWrapper"
__module_version__ = "0.1.0"
__module_license__ = "GPLv3"
__module_description__ = "A GPG wrapper plugin for HexChat."
__module_author__ = "github.com/kevinli"

import os
import subprocess
import threading

import hexchat

startupinfo = None
if os.name == "nt":
    # So the console window doesn't pop up
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

def encrypt_message(recipient, user, data, options):
    "Pipes data to gpg to be encrypted."
    popen_list = [
        "gpg.exe",
        "--trust-model", "always",
        "--encrypt",
        "--recipient", recipient,
        "--armor"
    ]
    if options and "s" in options and user:
        popen_list.append("--sign")
        popen_list.append("--local-user")
        popen_list.append(user)
    stdout, stderr = subprocess.Popen(
        popen_list,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        startupinfo=startupinfo
    ).communicate(bytes(data, "UTF-8"))
    return stdout.decode("UTF-8")

def decrypt_message(context, data):
    "Decrypts the received message and prints message with message information."
    popen_list = ["gpg.exe", "--batch", "--decrypt"]
    stdout, stderr = subprocess.Popen(
        popen_list,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        startupinfo=startupinfo
    ).communicate(bytes(data, "UTF-8"))
    # Printing is delayed when printing from a separate thread.
    info = stderr.decode("UTF-8").replace("\r", "").split("\n")
    for line in info:
        context.emit_print("Channel Message", "GPG", line)
    context.emit_print("Channel Message", "Message", stdout.decode("UTF-8"))

def sendmsg(word, word_eol, userdata):
    "Function called by /gpg. Parses user input, encrypts, and sends."
    channel = hexchat.get_info("channel")
    context = hexchat.find_context(channel=channel)
    if not userdata and len(word) < 3:
        context.emit_print("Channel Message", __module_name__, help_gpg)
        return hexchat.EAT_ALL
    elif userdata and len(word) < 4:
        context.emit_print("Channel Message", __module_name__, help_gpgs)
        return hexchat.EAT_ALL
    # Waiting for gpg-agent.exe to start and encrypt causes HexChat to hang.
    # Requires further testing with large messages.
    if not userdata:
        data = encrypt_message(word[1], None, word_eol[2], None)
    elif userdata and "s" in userdata:
        data = encrypt_message(word[1], word[2], word_eol[3], userdata)
    data = data.split("\n")
    for line in range(len(data)):
        data[line] = data[line].replace("\r", "")
        if data[line]: # Don't send blank lines
            context.emit_print(
                "Channel Message", hexchat.get_info("nick"), data[line]
            )
            context.command(
                "PRIVMSG {0} {1}".format(channel, data[line])
            )
    return hexchat.EAT_ALL

capture = False
recv_gpg_msg = []
def recvmsg(word, word_eol, userdata):
    "Captures received PGP message to decrypt."
    global capture, recv_gpg_msg
    if word[1] == "-----BEGIN PGP MESSAGE-----":
        capture = True
        recv_gpg_msg.append(word[1])
        # Add a blank line for the OpenPGP armor header.
        # This fails to work if the sender's message includes header tags.
        recv_gpg_msg.append("")
    elif capture:
        recv_gpg_msg.append(word[1])
    if word[1] == "-----END PGP MESSAGE-----":
        capture = False
        context = hexchat.find_context(channel=hexchat.get_info("channel"))
        # Waiting for pinentry to return causes HexChat to hang.
        # Wait for pinentry in a separate thread.
        thread = threading.Thread(
            target=decrypt_message,
            args=(context, "\n".join(recv_gpg_msg))
        )
        thread.daemon = True
        thread.start()
        recv_gpg_msg = []
    return hexchat.EAT_NONE

help_gpg = "Usage: /gpg recipient message"
hook_gpg = hexchat.hook_command(
    "gpg", sendmsg,
    userdata=None, priority=hexchat.PRI_NORM,
    help=help_gpg)
help_gpgs = "Usage: /gpgs recipient sign_as message"
hook_gpgs = hexchat.hook_command(
    "gpgs", sendmsg,
    userdata=("s"), priority=hexchat.PRI_NORM,
    help=help_gpgs)
hexchat.hook_print("Channel Message", recvmsg)
hexchat.hook_print("Private Message", recvmsg)
hexchat.hook_print("Private Message to Dialog", recvmsg)

def unload(userdata):
    "Runs when plugin is unloaded. Not exactly necessary, but..."
    hexchat.unhook("Channel Message")
    hexchat.unhook("Private Message")
    hexchat.unhook("Private Message to Dialog")
    hexchat.unhook(hook_gpg)
    hexchat.emit_print(
        "Channel Message", __module_name__, __module_name__ + " unloaded!"
    )
hexchat.hook_unload(unload)

hexchat.emit_print(
    "Channel Message", __module_name__, __module_name__ + " loaded!"
)
