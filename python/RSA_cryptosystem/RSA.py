#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""@author: satsuma.blog ."""

from random import SystemRandom, randint
from hashlib import sha256
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

####################
# Global Variables #
####################

default_bit_length = 512
default_exponent = 65537
launch_gui = True

###########################
# Number Theory Functions #
###########################


def gcd_ext(a: int, b: int) -> tuple:
    """
    Output (gcd,x,y) such that gcd=ax+by.

    Parameters
    ----------
    a : int
        DESCRIPTION.
    b : int
        DESCRIPTION.

    Returns
    -------
    tuple
        DESCRIPTION.

    """
    if not(a % 1 == 0 and b % 1 == 0):
        print("Need to use integers for gcd.")
        return None
    if a == 0:
        return (abs(b), 0, abs(b)//b)
    else:
        quot = b//a

        g, x, y = gcd_ext(b % a, a)
        return (g, y - quot * x, x)


def modular_inverse(a: int, b: int) -> int:
    """
    Return the multiplicative inverse of a modulo b.

    Returns none if gcd(a,b) != 1

    Parameters
    ----------
    a : int
        DESCRIPTION.
    b : int
        DESCRIPTION.

    Returns
    -------
    int
        DESCRIPTION.

    """
    (g, x, y) = gcd_ext(a, b)
    if not g == 1:
        print('The numbers are not comprime')
        return None
    x = x % b
    return x


def miller_rabin(p: int, a: int) -> bool:
    """
    Required for function is_prime.

    Parameters
    ----------
    p : prime being tested
    a : witness

    Returns
    -------
    True if prime, else False.
    """
    e = p-1
    bin_string = bin(e)[2:]
    n = 1

    for i in range(len(bin_string)):

        # Applying the ROO test.
        n_squared = pow(n, 2, p)
        if n_squared == 1:
            if (n != 1) and (n != p-1):
                return False

        if bin_string[i] == '1':
            n = (n_squared*a) % p
        else:
            n = n_squared

    # Applying the FLT test.
    if n != 1:
        return False

    return True


def is_prime(p: int, num_wit: int = 50) -> bool:
    """
    Test if an integer is prime.

    Parameters
    ----------
    p : int
        DESCRIPTION.
    num_wit : int, optional
        DESCRIPTION. The default is 50.

    Returns
    -------
    bool
        DESCRIPTION.

    """
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    if p <= 37:
        return p in small_primes

    if p % 2 == 0:
        return False

    if p <= pow(2, 64):
        for witness in small_primes:
            if not miller_rabin(p, witness):
                return False
        return True

    else:
        for i in range(num_wit):
            if not miller_rabin(p, randint(2, p-2)):
                return False
        return True


def random_prime(Bit_Length: int = default_bit_length) -> int:
    """
    Generate a random prime.

    Parameters
    ----------
    Bit_Length : int, optional
        The number of digits in the binary representation of the prime.
        e.g. a 512 bit prime is between 2**511 and 2**512

    Returns
    -------
    int
        A random prime.
    """
    while True:
        p = SystemRandom().getrandbits(Bit_Length)
        if p >= pow(2, Bit_Length-1):
            if is_prime(p):
                return p


def decimal_to_base(number: int, alphabet: list = [str(i) for i in range(10)] + [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)]) -> str:
    """
    

    Parameters
    ----------
    number : int
        DESCRIPTION.
    alphabet : list, optional
        DESCRIPTION. The default is [str(i) for i in range(10)] + [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)].

    Returns
    -------
    str
        DESCRIPTION.

    """
    base = len(alphabet)
    i = 1
    while True:
        if number//pow(base, i) == 0:
            i -= 1
            break
        i += 1
    base_list = []
    for j in range(i+1):
        base_list.append(alphabet[0])
    l = len(base_list)
    for j in range(l):
        x = pow(base, l-j-1)
        base_list[j] = alphabet[number//x]
        number -= alphabet.index(base_list[j])*x
    base_string = ''.join(base_list)
    return base_string


def base_to_decimal(base_string: str, alphabet: list = [str(i) for i in range(10)] + [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)]) -> int:
    decimal = 0
    base = len(alphabet)
    for i in range(1, len(base_string)+1):
        decimal += alphabet.index(base_string[-i])*pow(base, i-1)
    return decimal

################
# RSA Back End #
################


class Message(object):
    """Represents a message to be signed, encrypted and sent."""
    start_of_signatures_message = '\n\n----------------------SIGNATURES----------------------\n'
    separator = '_'
    allowed_characters = [str(i) for i in range(10)] + [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)] + [' ', '.', chr(10), ',', "'", '"',
                                                                                                                             '`', '!', '?', ':', ';', '(', ')', '[', ']', '{', '}', '/', '|', '\\', '-', '_', '@', '%', '&', '#', '~', '=', '+', '*', '<', '>', '^', '$','€','£']

    def __init__(self, string: str):
        unsupported_chars = ''.join(list(dict.fromkeys(
            [char for char in string if char not in Message.allowed_characters])))
        if unsupported_chars != '':
            print(
                '\nWARNING: message contains unsupported character(s): ' + unsupported_chars)
        self.string = string
        self.signatures = {}
        if Message.start_of_signatures_message in string:
            self.string = string[:string.index(
                Message.start_of_signatures_message)]
            signatures_string = string[string.index(
                Message.start_of_signatures_message) + len(Message.start_of_signatures_message):]
            labels_list = [i for i in range(
                len(signatures_string)) if signatures_string[i] == ':']
            other_list = [signatures_string[labels_list[j]+2:labels_list[j+1]]
                          for j in range(len(labels_list)-1)] + [signatures_string[labels_list[-1]+2:]]
            for i in range(len(other_list)//2):
                self.signatures[str(import_key(other_list[i*2]))] = base_to_decimal(
                    other_list[i*2+1][:other_list[i*2+1].index("\n")])
        self.h = int(sha256(self.string.encode()).hexdigest(), 16)

        self.verify()

    def __str__(self):
        text_string = self.string
        if self.signatures != {}:
            text_string += Message.start_of_signatures_message
            for pub_key in self.signatures:
                text_string += '\nPUBLIC KEY:\n' + pub_key + '\nSIGNATURE:\n' + \
                    decimal_to_base(self.signatures[pub_key]) + '\n'
        return text_string

    def verify(self):
        reverse_dict = {}
        for key in Key_Store.public_keys:
            reverse_dict[str(Key_Store.public_keys[key])] = key
        txt = ''
        if self.signatures == {}:
            txt = 'Message has not been signed.'
        else:
            valid_sigs = []
            invalid_sigs = []
            for pub_key in self.signatures:
                if self.h == pow(self.signatures[pub_key], import_key(pub_key).e, import_key(pub_key).N):
                    if str(pub_key) in reverse_dict:
                        valid_sigs.append(reverse_dict[pub_key])
                    else:
                        valid_sigs.append(str(pub_key))
                else:
                    if str(pub_key) in reverse_dict:
                        invalid_sigs.append(reverse_dict[pub_key])
                    else:
                        invalid_sigs.append(str(pub_key))
            if invalid_sigs != []:
                if txt != '':
                    txt += '\n'
                txt += 'WARNING! \nInvalid signature(s) from:\n' + '\n'.join(invalid_sigs)
            if valid_sigs != []:
                if txt != '':
                    txt += '\n'
                txt += 'Valid signature(s) from:\n' + '\n'.join(valid_sigs)
        return txt


def de_format(any_string: str) -> list:
    separators = [i for i in range(
        len(any_string)) if any_string[i] == Message.separator]
    de_formatted = [base_to_decimal(
        any_string[separators[i]+1:separators[i+1]]) for i in range(len(separators)-1)]
    return de_formatted


class Key(object):
    """Represents a generic key."""

    def __str__(self):
        string = self.prefix + Message.separator
        for i in range(2):
            string += decimal_to_base(list(self.__dict__.values())
                                      [i]) + Message.separator
        return string


class Private_Key(Key):
    """Represents a private key."""
    
    def __init__(self, p: int = 'new', q: int = 'new', Bit_Length: int = default_bit_length, label: str = ''):
        self.p = p
        self.q = q
        if p == 'new' or q == 'new':
            print('\nGenerating two random ' + str(Bit_Length) +
                  ' bit primes to form a new private key...\n')
            self.p = random_prime(Bit_Length)
            self.q = random_prime(Bit_Length)
        self.pub_key = Public_Key(self.p*self.q, label=label)
        self.d = modular_inverse(
            self.pub_key.e, (self.pub_key.N - self.p - self.q + 1))
        if label == '':
            self.label = str(Bit_Length)+'_Bit_Private_Key'
        self.label = label

    prefix = 'privkey'

    def decrypt(self, ciphertext: str) -> Message:
        cipher_list = de_format(ciphertext)
        sub_message_decimal_list = [str(pow(c, self.d, self.pub_key.N))[
            1:] for c in cipher_list]
        sub_message_list = [[Message.allowed_characters[int(
            decimal[2*i:2*i+2])] for i in range(len(decimal)//2)] for decimal in sub_message_decimal_list]
        return Message(''.join([''.join(sub_message) for sub_message in sub_message_list]))

    def sign(self, message: Message) -> dict:
        message.signatures[str(self.pub_key)] = pow(
            message.h, self.d, self.pub_key.N)
        return message.signatures


class Public_Key(Key):
    """Represents a public key."""

    def __init__(self, N: int, e: int = default_exponent, label: str = ''):
        self.N = N
        self.e = e
        if label == '':
            self.label = str(len(bin(N)[2:]))+'_Bit_Public_Key'
        self.label = label

    prefix = 'pubkey'

    def encrypt(self, message: Message) -> str:
        sub_message_chr_length = int((len(bin(self.N)[2:])/2)*0.3)
        text_string = str(message)
        number_of_sub_messages = len(text_string)//sub_message_chr_length
        sub_message_list = [text_string[i*sub_message_chr_length:(i+1)*sub_message_chr_length] for i in range(
            number_of_sub_messages)] + [text_string[number_of_sub_messages*sub_message_chr_length:]]
        decimal_list = [['%.2d' % Message.allowed_characters.index(
            char) for char in sub_message] for sub_message in sub_message_list]
        encrypted_list = [pow(int('1' + ''.join(i)), self.e, self.N)
                          for i in decimal_list]
        return 'ciphertext' + Message.separator + Message.separator.join([decimal_to_base(i) for i in encrypted_list]) + Message.separator


def import_key(string: str):
    if string[:len(Private_Key.prefix)] == Private_Key.prefix:
        p, q = de_format(string)
        return Private_Key(p, q)

    if string[:len(Public_Key.prefix)] == Public_Key.prefix:
        N, e = de_format(string)
        return Public_Key(N, e)

    print("ERROR: No valid key!")


def test():
    """
    Test if everything is working.

    Returns
    -------
    None.

    """
    print('TESTING...')
    Alice_Key = Private_Key()
    print("Alice's Key Pair:\n\n" + str(Alice_Key) +
          '\n\n' + str(Alice_Key.pub_key))
    Bob_Key = Private_Key()
    print("Bob's Key Pair:\n\n" + str(Bob_Key) + '\n\n' + str(Bob_Key.pub_key))
    assert Bob_Key.p != Alice_Key.p
    assert Bob_Key.p != Alice_Key.q
    assert Bob_Key.q != Alice_Key.p
    assert Bob_Key.q != Alice_Key.q
    assert Bob_Key.p != Bob_Key.q
    assert Alice_Key.p != Alice_Key.q
    string = """In common parlance, randomness is the apparent or actual lack
of pattern or predictability in events.[1][2] A random sequence of events,
symbols or steps often has no order and does not follow an intelligible pattern
or combination. Individual random events are, by definition, unpredictable, but
if the probability distribution is known, the frequency of different outcomes
over repeated events (or "trials") is predictable.[3][note 1] For example, when
throwing two dice, the outcome of any particular roll is unpredictable, but a
sum of 7 will tend to occur twice as often as 4. In this view, randomness is
not haphazardness; it is a measure of uncertainty of an outcome. Randomness
applies to concepts of chance, probability, and information entropy."""
    print("\nAlice wants to send Bob the message:\n\n" + string)
    Alice_message = Message(string)
    print("\nShe signs it then encrypts it with Bob's public key.\n")
    Alice_Key.sign(Alice_message)
    print(Alice_message)
    print(Alice_message.verify())
    ciphertext = import_key(str(Bob_Key.pub_key)).encrypt(Alice_message)
    print(ciphertext)
    print('\nBob decrypts this using his private key.\n')
    decrypted_message = Bob_Key.decrypt(ciphertext)
    assert decrypted_message.string == string
    print(decrypted_message)
    print("""Bob decides to edit the message and then sign the message as well
          as then sending it back to Alice.\n""")
    new_message = Message('Bob is awesome! ' + str(decrypted_message))
    Bob_Key.sign(new_message)
    print(new_message)
    ciphertext2 = import_key(str(Alice_Key.pub_key)).encrypt(new_message)
    print(ciphertext2)
    print("""\nAlice decrypts the message, noticing that her signature is no
longer valid as Bob edited the message.\n""")
    decrypted_message2 = Alice_Key.decrypt(ciphertext2)
    print(decrypted_message2)
    print(decrypted_message2.verify())
    return


#############
# Key Store #
#############

class Key_Store(object):
    private_keys = {}
    public_keys = {}
    key_file = 'keys.txt'

    def read_keys():
        try:
            open(Key_Store.key_file, 'x')
        except:
            pass
        keys_list = open(Key_Store.key_file, 'r').read().split()
        if 'Public_Key(s):' in keys_list:
            pub_key_list = keys_list[keys_list.index('Public_Key(s):')+1:]
            if 'Private_Key(s):' in keys_list:
                keys_list = keys_list[keys_list.index('Private_Key(s):')+1:keys_list.index('Public_Key(s):')] + pub_key_list
            else:
                keys_list = pub_key_list

        labels = [keys_list[2*i] for i in range(len(keys_list)//2)]
        keys = [import_key(keys_list[2*i + 1]) for i in range(len(keys_list)//2)]
        if keys != []:
            for i in range(len(keys)):
                try:
                    keys[i].label = labels[i]
                    if type(keys[i]) == Private_Key:
                        Key_Store.private_keys[keys[i].label] = keys[i]
                    else:
                        Key_Store.public_keys[keys[i].label] = keys[i]
                except:
                    pass

        for key in Key_Store.private_keys:
            Key_Store.public_keys[key] = Key_Store.private_keys[key].pub_key


    def write_keys():
        for key in Key_Store.private_keys:
            Key_Store.public_keys[key] = Key_Store.private_keys[key].pub_key

        Private_Keys_txt = 'Private_Key(s):\n'
        Public_Keys_txt = '\nPublic_Key(s):\n'
        
        for key in Key_Store.private_keys:
            Private_Keys_txt += str(key)+'\n'+str(Key_Store.private_keys[key])+'\n'
        for key in Key_Store.public_keys:
            Public_Keys_txt += str(key)+'\n'+str(Key_Store.public_keys[key])+'\n'
        with open(Key_Store.key_file, '+w') as f:
            f.write(Private_Keys_txt+Public_Keys_txt)


#######
# GUI #
#######

class Main_Window(object):
    def __init__(self):
        self.root= tk.Tk()
        self.root.title('RSA cryptosystem')
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        self.style = ttk.Style()
        self.theme_var = tk.StringVar()
        
        root_width=800
        root_height=600

        positionRight = int(self.root.winfo_screenwidth()/2 - root_width/2 )
        positionDown = int(self.root.winfo_screenheight()/2 - root_height/2 ) - 50

        self.root.geometry("{}x{}+{}+{}".format(root_width, root_height, positionRight, positionDown))

main_window = Main_Window()

#################
# Key selection #
#################

key_selection_frame = ttk.Frame(main_window.root)
key_selection_frame.columnconfigure(1, weight=1)
key_selection_frame.grid(row=0, column=0, sticky=tk.N +
                         tk.E+tk.S+tk.W, padx=10, pady=4)


class Key_selection(object):
    def __init__(self, label: str, row: int,):
        ttk.Label(key_selection_frame, text=label).grid(
            row=row, column=0, sticky=tk.W)
        self.key_var = tk.StringVar()
        self.options = ttk.OptionMenu(
            key_selection_frame, self.key_var, "No Keys (click 'Import')")
        self.options.grid(row=row, column=1, sticky=tk.W+tk.E, padx=25)


private_key_selection = Key_selection("Private Key:", 0)
public_key_selection = Key_selection("Public Key:", 1)


class import_export_btns(object):
    def __init__(self, label, row):
        self.btn = tk.Button(key_selection_frame, text=label, padx=2)
        self.btn.grid(row=row, column=2)


import_btn = import_export_btns('Import', 0)
export_btn = import_export_btns('Export', 1)

########################################
##### Message and Ciphertext boxes #####
########################################

message_frame = ttk.Frame(main_window.root)
message_frame.grid(row=1, sticky=tk.N+tk.E+tk.S+tk.W, ipadx=2, ipady=2)
for i in range(2):
    message_frame.columnconfigure(i, weight=1)
message_frame.rowconfigure(0, weight=1)


class Message_box(object):
    def __init__(self, label, column):
        self.frame = ttk.LabelFrame(message_frame, text=label)
        for i in range(2):
            self.frame.columnconfigure(i, weight=1)
        self.frame.rowconfigure(0, weight=1)
        self.frame.grid(row=0, column=column,
                        sticky=tk.N+tk.E+tk.S+tk.W, padx=2, pady=4)
        self.text = tk.Text(self.frame)
        self.text.grid(row=0, column=0, sticky=tk.N +
                       tk.E+tk.S+tk.W, columnspan=2)


message_input = Message_box("Message:", 0)
ciphertext_input = Message_box("Ciphertext:", 1)

###########
# Buttons #
###########


class Lower_btn(object):
    """Represents the lower buttons."""

    def __init__(self, label: str, frame, column: int):
        self.btn = ttk.Button(frame, text=label)
        self.btn.grid(row=1, column=column, sticky=tk.E+tk.W, padx=2, ipady=2)


sign_btn = Lower_btn('Sign', message_input.frame, 0)
encrypt_btn = Lower_btn('Encrypt', message_input.frame, 1)
decrypt_btn = Lower_btn('Decrypt', ciphertext_input.frame, 0)
verify_btn = Lower_btn('Verify', ciphertext_input.frame, 1)

###################################
# Callback Functions and Bindings #
###################################

def Sign():
    if private_key_selection.key_var.get() not in Key_Store.private_keys:
        messagebox.showwarning(title="No Private Key", message="Select a private key")
        return
    priv_key = Key_Store.private_keys[private_key_selection.key_var.get()]
    message = Message(message_input.text.get('1.0', tk.END))
    priv_key.sign(message)
    message_input.text.delete('1.0', tk.END)
    message_input.text.insert('1.0', str(message))


sign_btn.btn.configure(command=Sign)


def Encrypt():
    if public_key_selection.key_var.get() not in Key_Store.public_keys:
        messagebox.showwarning(title="No Public Key", message="Select a public key")
        return
    pub_key = Key_Store.public_keys[public_key_selection.key_var.get()]
    message = Message(message_input.text.get('1.0', tk.END))
    unsupported_chars = [i for i in message.string if i not in Message.allowed_characters]
    unsupported_chars = list(dict.fromkeys(unsupported_chars))
    if unsupported_chars != []:
        messagebox.showwarning(title="Unsupported Character", message="ERROR!\nMessage contains unsupported character(s):\n"+', '.join(unsupported_chars))
        return
    ciphertext = pub_key.encrypt(message)
    message_input.text.delete('1.0', tk.END)
    message_input.text.insert('1.0', ciphertext)


encrypt_btn.btn.configure(command=Encrypt)


def Decrypt():
    if private_key_selection.key_var.get() not in Key_Store.private_keys:
        messagebox.showwarning(title="No Private Key", message="Select a private key")
        return
    priv_key = Key_Store.private_keys[private_key_selection.key_var.get()]
    ciphertext = ciphertext_input.text.get('1.0', tk.END)
    try:
        message = priv_key.decrypt(ciphertext)
    except:
        messagebox.showwarning(title="Wrong private key", message="Wrong private key")
        return
    message = priv_key.decrypt(ciphertext)
    ciphertext_input.text.delete('1.0', tk.END)
    ciphertext_input.text.insert('1.0', str(message))

decrypt_btn.btn.configure(command=Decrypt)


def Verify():
    message = Message(ciphertext_input.text.get('1.0', tk.END))
    verify_txt = message.verify()

    messagebox.showinfo("Signature verification", verify_txt)


verify_btn.btn.configure(command=Verify)


def update_key_OptionMenu():
    if list(Key_Store.private_keys) != []:
        private_key_selection.key_var.set(list(Key_Store.private_keys)[0])
        private_key_selection.options["menu"].delete(0, tk.END)
        for key in list(Key_Store.private_keys):
            private_key_selection.options["menu"].add_command(
                label=key, command=tk._setit(private_key_selection.key_var, key))
    else:
        private_key_selection.key_var.set("No Keys (click 'Import')")
        private_key_selection.options["menu"].delete(0, tk.END)
    if list(Key_Store.public_keys) != []:
        public_key_selection.key_var.set(list(Key_Store.public_keys)[0])
        public_key_selection.options["menu"].delete(0, tk.END)
        for key in list(Key_Store.public_keys):
            public_key_selection.options["menu"].add_command(
                label=key, command=tk._setit(public_key_selection.key_var, key))
    else:
        public_key_selection.key_var.set("No Keys (click 'Import')")
        public_key_selection.options["menu"].delete(0, tk.END)


def Import(new_key=False):
    popup = tk.Toplevel(main_window.root)
    popup.title('Import Key')
    def destroy_popup(event):
        popup.destroy()
    popup.bind('<Command-Key-w>', destroy_popup)
    
    popup_width=450
    popup_height=165
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))
    popup.resizable(False, False)

    label_frame = ttk.LabelFrame(popup, text='Label')
    label_frame.pack(fill=tk.BOTH, padx=4)
    label_var = tk.StringVar()
    tk.Entry(label_frame, textvariable=label_var).pack(fill=tk.BOTH)

    key_frame = ttk.LabelFrame(popup, text='Key')
    key_frame.pack(fill=tk.BOTH, padx=4)
    key_txt = tk.Text(key_frame, height=3)
    key_txt.pack(fill=tk.BOTH)

    option_frame = ttk.Frame(popup)
    option_frame.pack()

    ttk.Label(option_frame, text="Bit length:").grid(column=0, row=0)

    bit_length_choice = tk.IntVar()
    ttk.OptionMenu(option_frame, bit_length_choice, 2**9, 2**8, 2 **
                   9, 2**10, 2**11, 2**12).grid(column=1, row=0, padx=2, pady=6)

    # New Key button
    def new():
        key_txt.delete('1.0', tk.END)
        key_txt.insert('1.0', str(Private_Key(
            Bit_Length=bit_length_choice.get())))
    
    if new_key == True:
        new()
    else:
        key_txt.delete('1.0',tk.END)

    ttk.Button(option_frame, text="New Private Key",
               command=new).grid(column=2, row=0, padx=4)

    # Save button
    def save():
        key = import_key(key_txt.get('1.0', tk.END))
        label = label_var.get()
        label = ''.join([label[i]
                        for i in range(len(label)) if label[i] != ' '])

        if label == '':
            messagebox.showwarning("Error", "Key must have a label")
            return
        if label in list(Key_Store.public_keys):
            if label in list(Key_Store.private_keys):
                answer = messagebox.askokcancel(
                    "Warning", "Private Key with that label already exists.")
                if answer:
                     pass
                else:
                    return
            else:
                answer = messagebox.askokcancel(
                    "Warning", "Public Key with that label already exists.")
                if answer:
                    pass
                else:
                    return

        if type(key) == Private_Key:
            Key_Store.private_keys[label] = key
            Key_Store.write_keys()
            update_key_OptionMenu()
            popup.destroy()
        elif type(key) == Public_Key:
            Key_Store.public_keys[label] = key
            Key_Store.write_keys()
            update_key_OptionMenu()
            popup.destroy()
        else:
            messagebox.showwarning("Error", "No valid key entered.")
            return

    ttk.Button(option_frame, text="Save", command=save).grid(
        column=3, row=0, padx=4)


import_btn.btn.configure(command=Import)
def Import_event(event=None):
    Import(new_key=True)

def Export():
    popup = tk.Toplevel()
    popup.title('Keys')
    def destroy_popup(event):
        popup.destroy()
    popup.bind('<Command-Key-w>', destroy_popup)
    
    popup_width=500
    popup_height=300
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))
    
    keys_text = tk.Text(popup, height=100)
    keys_text.insert('1.0', open('keys.txt', 'r').read())
    keys_text["state"] = tk.DISABLED
    keys_text.pack(fill=tk.BOTH)


export_btn.btn.configure(command=Export)


def view_pub_keys():
    your_pub_key_dict = {}
    for key in Key_Store.private_keys:
        your_pub_key_dict[key] = Key_Store.private_keys[key]
    
    popup = tk.Toplevel()
    popup.title('Your Public Keys')
    def destroy_popup(event):
        popup.destroy()
    popup.bind('<Command-Key-w>', destroy_popup)
    
    popup_width=500
    popup_height=300
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))
    
    keys_text = tk.Text(popup, height=100)
    for key in your_pub_key_dict:
        keys_text.insert(tk.END, str(key)+'\n'+str(your_pub_key_dict[key].pub_key)+'\n')
    keys_text["state"] = tk.DISABLED
    keys_text.pack(fill=tk.BOTH)


def Delete_Key():
    popup = tk.Toplevel()
    popup.title('Delete Key')
    def destroy_popup(event):
        popup.destroy()
    popup.bind('<Command-Key-w>', destroy_popup)
    for i in range(2):
        popup.columnconfigure(i, weight=1)
    
    popup_width=450
    popup_height=180
    positionRight = int(popup.winfo_screenwidth()/2 - popup_width/2 )
    positionDown = int(popup.winfo_screenheight()/2 - popup_height/2 ) - 150
    popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, positionRight, positionDown))
    popup.resizable(False, False)
    
    var=tk.StringVar()
    ttk.Radiobutton(popup, text='Private Key', var=var, value='Private Key').grid(row=0, column=0, sticky=tk.W, padx=4, pady=2)
    ttk.Radiobutton(popup, text='Public Key', var=var, value='Public Key').grid(row=1, column=0, sticky=tk.W, padx=4, pady=2)
    
    selected_key = tk.StringVar()
    key_options = ttk.OptionMenu(popup, selected_key, "No Keys")
    key_options.grid(row=2, column=0, columnspan=2, sticky=tk.W+tk.E, padx=6, pady=4)
    
    key_txt = tk.Text(popup, height=4, state=tk.DISABLED)
    key_txt.grid(row=3, column=0, columnspan=2, sticky=tk.W+tk.E, padx=4)
     
    def update_delete_key_options(*args):
        key_list = []
        if var.get() == 'Private Key':
            key_list = list(Key_Store.private_keys)
        if var.get() == 'Public Key':
            key_list = list(Key_Store.public_keys)
            for key in list(Key_Store.private_keys):
                if key in key_list:
                    key_list.remove(key)
        if key_list != []:
            key_options["menu"].delete(0, tk.END)
            selected_key.set(key_list[0])
            for key in key_list:
                key_options["menu"].add_command(label=key, command=tk._setit(selected_key, key))
        if key_list == []:
            key_options["menu"].delete(0, tk.END)
            selected_key.set("No Keys")
            
    var.trace_add('write', update_delete_key_options)
    
    def update_key_txt(*args):
        key_txt["state"] = tk.NORMAL
        key_txt.delete('1.0', tk.END)
        if var.get() == 'Private Key':
            if selected_key.get() == "No Keys":
                delete_key_btn["state"] = tk.DISABLED
            else:
                key_txt.insert('1.0', Key_Store.private_keys[selected_key.get()])
                delete_key_btn["state"] = tk.NORMAL
        if var.get() == 'Public Key':
            if selected_key.get() == "No Keys":
                delete_key_btn["state"] = tk.DISABLED
            else:
                key_txt.insert('1.0', Key_Store.public_keys[selected_key.get()])
                delete_key_btn["state"] = tk.NORMAL
        key_txt["state"] = tk.DISABLED
    
    selected_key.trace_add('write', update_key_txt)
    
    def delete_all_keys():
        answer = messagebox.askokcancel(title="WARNING!", message="WARNING!\nThis will delete all keys, public and private")
        if answer:
            Key_Store.private_keys = {}
            Key_Store.public_keys = {}
            Key_Store.write_keys()
            update_delete_key_options()
            update_key_OptionMenu()
            popup.destroy()
        
    ttk.Button(popup, text="Delete All Keys", command=delete_all_keys).grid(row=4, column=0)
    
    def delete_key():
        key = selected_key.get()
        if var.get() == 'Private Key':
            answer =  messagebox.askokcancel(title="WARNING!", message="WARNING!\nThis will delete the private key:\n"+str(key)+"\nAND it's corresponding public key")
            if answer:
                del Key_Store.public_keys[key]
                del Key_Store.private_keys[key]
                Key_Store.write_keys()
                update_delete_key_options()
                update_key_OptionMenu()
                popup.destroy()
        if var.get() == 'Public Key':
            answer =  messagebox.askokcancel(title="WARNING!", message="WARNING!\nThis will delete the public key:\n"+str(key))
            if answer:
                del Key_Store.public_keys[key]
                Key_Store.write_keys()
                update_delete_key_options()
                update_key_OptionMenu()
                popup.destroy()
                
    delete_key_btn = ttk.Button(popup, text="Delete Key", command=delete_key)
    delete_key_btn["state"] = tk.DISABLED
    delete_key_btn.grid(row=4, column=1)

def Delete_Key_event(event):
    Delete_Key()
    
def set_theme(*args):
    theme = main_window.theme_var.get()
    main_window.style.theme_use(theme)

main_window.theme_var.trace_add('write', set_theme)

def clear(text_input):
    text_input.text.delete('1.0', tk.END)

def clear_Message():
    clear(message_input)

def clear_Ciphertext():
    clear(ciphertext_input)

def clear_Both():
    clear_Message()
    clear_Ciphertext()

def clear_Both_event(event):
    clear_Both()

########
# Menu #
########

menu = tk.Menu(main_window.root, tearoff=0)
main_window.root.configure(menu=menu)

keys_menu = tk.Menu(menu, tearoff=0)
keys_menu.add_command(label='View public keys', command=view_pub_keys)
keys_menu.add_command(label='New key', command=Import_event, accelerator="Command+N")
keys_menu.add_command(label='Delete key', command=Delete_Key, accelerator="Command+D")
menu.add_cascade(label='Keys', menu=keys_menu)

view_menu = tk.Menu(menu, tearoff=0)
theme_menu = tk.Menu(menu, tearoff=0)
for theme in main_window.style.theme_names():
    theme_menu.add_radiobutton(label=theme, value=theme, variable=main_window.theme_var)
view_menu.add_cascade(label='Theme', menu=theme_menu)
menu.add_cascade(label='View', menu=view_menu)

clear_menu = tk.Menu(menu, tearoff=0)
clear_menu.add_command(label="Clear Message", command=clear_Message)
clear_menu.add_command(label="Clear Ciphertext", command=clear_Ciphertext)
clear_menu.add_command(label="Clear All", command=clear_Both, accelerator="command+BackSpace")
menu.add_cascade(label='Clear', menu=clear_menu)

#########
# Binds #
#########

main_window.root.bind_all('<Command-Key-d>', Delete_Key_event)
main_window.root.bind_all('<Command-Key-n>', Import_event)
main_window.root.bind_all('<Command-Key-BackSpace>', clear_Both_event)

#################
# Launching GUI #
#################

if launch_gui:
    Key_Store.read_keys()
    update_key_OptionMenu()
    main_window.root.mainloop()
    Key_Store.write_keys()
