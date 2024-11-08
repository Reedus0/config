import re
from logger import *
from file import *

def find_regex(regex, string, group_count):
    result = []
    regex_result = re.search(re.compile(regex), string)

    if(not regex_result): 
        return []
    for i in range(1, group_count + 1):
        result.append(regex_result.group(i))

    return result

def find_ip_and_port(file):
    log(f"Looking for IP and port of C2...")

    file_data = read_file(file)
    """
    push    C2_PORT
    push    offset C2_SERVER
    push    eax  
    call    InternetConnectW_0
    add     esp, 0Ch
    """
    c2_info_regex = (
        b"[\\x6A\\x68](.{1,4})"
        b"\\x68(.{4})"
        b"\\x50"
        b"\\xE8.{4}"
        b"\\x83\\xC4\\x0C"
    )
    result = find_regex(c2_info_regex, file_data, 2)
    if (len(result)):
        log(f"Found IP and port of C2!")
        return [read_pe_string(file, int.from_bytes(result[1], "little")), int.from_bytes(result[0], "little")]
    else:
        log(f"Didn't found IP and port of C2...")
        return []
    
def find_user_agent(file):
    log(f"Looking for user agent...")

    file_data = read_file(file)
    """
    push    0
    push    0 
    push    0
    push    1
    push    offset USER_AGENT
    call    ds:InternetOpenW
    retn
    """
    c2_info_regex = (
        b"\\x6A\\x00"
        b"\\x6A\\x00"
        b"\\x6A\\x00"
        b"\\x6A\\x01"
        b"\\x68(.{1,4})"
        b"\\xFF\\x15.{4}"
        b"\\xC3"
    )
    result = find_regex(c2_info_regex, file_data, 1)
    if (len(result)):
        log(f"Found user agent!")
        return read_pe_string(file, int.from_bytes(result[0], "little"))
    else:
        log(f"Didn't found user agent...")
        return ""
    
def find_c2_url(file):
    log(f"Looking for C2 url...")

    file_data = read_file(file)
    """
    push    offset aC2Php   ; "/c2.php"
    push    edi             ; lpString1
    call    ds:lstrcpyW
    mov     esi, ds:lstrcatW
    push    offset aActionInstalln ; "?action=installnewbot"
    push    edi             ; lpString1
    call    esi ; lstrcatW
    push    offset aUsername ; "&Username="
    push    edi             ; lpString1
    call    esi ; lstrcatW
    """
    c2_info_regex = (
        b"\\x68(.{1,4})"
        b"\\x57"
        b"\\xFF\\x15.{4}"
        b"\\x8B\\x35.{4}"
        b"\\x68.{4}"
        b"\\x57"
        b"\\xFF\\xD6"
        b"\\x68.{4}"
        b"\\x57"
        b"\\xFF\\xD6"
    )
    result = find_regex(c2_info_regex, file_data, 1)
    if (len(result)):
        log(f"Found C2 url!")
        return read_pe_string(file, int.from_bytes(result[0], "little"))
    else:
        log(f"Didn't found C2 url...")
        return ""
    
def find_content_type(file):
    log(f"Looking for content type...")

    file_data = read_file(file)
    """
    push    0               ; lpszReferrer
    push    0               ; lpszVersion
    push    [ebp+lpszObjectName] ; lpszObjectName
    mov     [ebp+lpszAcceptTypes], offset aText ; "text/*"
    push    edi             ; lpszVerb
    push    [ebp+hConnect]  ; hConnect
    mov     [ebp+var_4], 0
    call    ds:HttpOpenRequestW
    """
    c2_info_regex = (
        b"\\x6A\\x00"
        b"\\x6A\\x00"
        b"\\xFF\\x75."
        b"\\xC7\\x45.(.{1,4})"
        b"\\x57"
        b"\\xFF\\x75."
        b"\\xC7\\x45..{4}"
        b"\\xFF\\x15.{4}"
    )
    result = find_regex(c2_info_regex, file_data, 1)
    if (len(result)):
        log(f"Found content type!")
        return read_pe_string(file, int.from_bytes(result[0], "little"))
    else:
        log(f"Didn't found content type...")
        return ""