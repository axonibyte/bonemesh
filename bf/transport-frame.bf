; transport_frame_poke __ BMX transport frame sealing in brainfuck;
;
; Reproduces spec/corpus/transcripts/transport_frame_json:
;
; ct = ChaCha20_Poly1305(key nonce empty AAD inner_plaintext)
; where nonce is FOUR ZERO BYTES then the 64 bit little endian seq
;
; That nonce construction is the BoneMesh part and it is what this program
; does; Everything else is handed straight to aead/chacha20poly1305_bf which
; is bfsodium's and is checked against RFC 8439 in bfsodium's own suite;
;
; IO  in:  key{32}  seq{8} LE  plen{2} LE  pt{plen}
; out: ciphertext{plen}  tag{16}
;
; The caller supplies seq as eight little endian bytes because that is the
; order the nonce wants them in; there is no byte swapping here and there is
; not meant to be; interop/check_transport_bf_sh builds that input out of the
; corpus with sed and xxd __ the same division every other port makes since
; the Go port reads the vector with Go's JSON parser rather than with Go's
; crypto; Every cryptographic operation happens below this line;
;
; WHY THE PROGRAM DOES NOT JUST RELAY; bfsodium's AEAD wants
; key{32} nonce{12} alen{2} aad{alen} plen{2} pt{plen} and the caller's bytes
; are neither that shape nor that length: four zero nonce bytes and a two byte
; zero AAD length have to be INSERTED between fields the caller supplied; A
; relay could not do it and the insertion is exactly the protocol detail the
; corpus is freezing;
;
; TAPE MAP
; cell 0 is the working cell: every EMIT and every READ uses it;
; cell 1 holds the status byte of a read;
; cell 3 holds one byte in flight;
; cell 4 is the branch flag: set before a read cleared by an END status;
; cell 5 counts down a forward of known length;
; cell 9 holds a reply's declared payload length while it is drained;
;
; INDENTATION IS LOAD BEARING; A comment indented by two or more spaces
; annotates the frame that follows it; a flush one is the file talking about
; itself;
;
; Frames transcribed by hand from brainstem's ABI_md sections 3 7_10 to 7_16;
;
; hello  op 01 len 10 want major 1 and MINOR 1 __ the spawn below sends a
; zero length path which only a 1_1 broker reads as "the interpreter you
; are already running under";
+.+++++++++.----------.+++++++++++++++++++++++++++++++++++++
  +++++++++++++++++++++++++++++.+++++++++++++++++.+.-------.   ; continued
  ----------------------------------------------------------   ; continued
  ------------------.-.+.-...                                  ; continued
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
  ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,              ; continued
                                                               ; pipe  op 0e flags 0;  Handles 4 (read) and 5 (write):
                                                               ; this program writes the AEAD's input into 5 and the
                                                               ; routine reads it from 4;
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
                                                               ; pipe again;  Handles 6 (read) and 7 (write): the
                                                               ; routine writes the sealed frame into 7 and this
                                                               ; program reads it from 6;
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
                                                               ; spawn  op 0f len 0x30 = 48; dir ffffffff meaning the
                                                               ; broker's working directory flags 0 nfdmap 2 nargv 2
                                                               ; nenv 0 reserved 0
[-]+++++++++++++++.+++++++++++++++++++++++++++++++++.-------
  -----------------------------------------.-....+..++..--..   ; continued
                                                               ; child fd 0 gets handle 4 child fd 1 gets handle 7;
                                                               ; Any descriptor not named here is closed so the
                                                               ; routine gets these two and nothing else;
.++++.----...
+.++++++.-------...
                                                               ; THE PATH IS EMPTY: the interpreter the broker
                                                               ; launched this program under;  Nothing here names an
                                                               ; interpreter so nothing here can name the wrong one;
..
+++.---.++++++++++++++++++++++++++++++++++++++++++++++++++++   ; argv{0} is the label "bfi" which nothing resolves
  ++++++++++++++++++++++++++++++++++++++++++++++.++++.+++.     ; continued
------------------------------------------------------------   ; argv{1} is the routine: "chacha20poly1305_bf"
  --------------------------.-------------------.+++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  ++++++++++++++++++++++++++++++.+++++.-------.++.+++++.----   ; continued
  ---.-----------------------------------------------.--.+++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  +++.-.---.+++++++++++++.----------------------------------   ; continued
  --------------------------------------.++.---.+++++.------   ; continued
  -.++++++++++++++++++++++++++++++++++++++++++++++++++++.+++   ; continued
  +.                                                           ; continued
,,,,,,,                                                        ; the reply is a process handle: 8
                                                               ; close the outer copies of the child's two ends;
                                                               ; Without this the routine never sees end of input and
                                                               ; this program never sees end of file;
[-]++++++++++++.--------.----.++++.----...
,,,
[-]++++++++++++.--------.----.+++++++.-------...
,,,
                                                               ; THE KEY thirty two bytes forwarded from the broker's
                                                               ; stdin to the routine's stdin;  cell 5 counts them
                                                               ; down;
>>>>>++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,                                                      ; cell 1 takes the status preset so that no reply at
                                                               ; all reads as END
>>>>+<<<                                                       ; cell 4 is the branch flag set on the way past
                                                               ; an END here means the caller sent a short input:
                                                               ; clear the status the branch flag and the counter
                                                               ; which ends this forward without a byte
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<                                                          ; cell 3 takes the byte then back to the working cell
[-]+++++++++++.----.-------.+++++.-----.....                   ; write  op 0b handle 5 flags 0 that byte
>>>.<<<
                                                               ; THE REPLY IS DRAINED BY ITS DECLARED LENGTH never by
                                                               ; an assumed one; A write that succeeds answers with
                                                               ; nwritten{2}; a write that FAILS answers with no
                                                               ; payload at all because ABI rule I6 says an error
                                                               ; reply never carries one; Reading five bytes
                                                               ; unconditionally swallows the next reply's first two
                                                               ; the moment a write fails and every frame after it is
                                                               ; shifted;
>[-]+,
>>>>>>>>[-],
<<<<<<<<<,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-                                                         ; one byte done: count it off inside the branch then
                                                               ; consume the flag
<[-]
]
>
]
<<<<<                                                          ; back to the working cell
                                                               ; THE NONCE PREFIX: four zero bytes in one write frame
                                                               ; rather than four; This is the first of the two
                                                               ; insertions __ the caller never sent these and the
                                                               ; AEAD requires them;  write op 0b len 0x0a = 10 handle
                                                               ; 5 flags 0;
[-]+++++++++++.-.----------.+++++.-----.........
,,,,,
                                                               ; THE SEQ eight bytes forwarded as the caller sent
                                                               ; them: little endian is already the order the nonce
                                                               ; wants so there is no swap here;
>>>>>++++++++
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.+++++.-----.....
>>>.<<<
>[-]+,
>>>>>>>>[-],
<<<<<<<<<,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
                                                               ; THE AAD LENGTH: two zero bytes the second insertion;
                                                               ; A BMX transport frame authenticates no additional
                                                               ; data __ the sequence number is in the nonce rather
                                                               ; than the AAD __ so this is zero and the routine reads
                                                               ; no aad bytes after it;
[-]+++++++++++.---.--------.+++++.-----.......
,,,,,
>>>>>++                                                        ; THE PLAINTEXT LENGTH two bytes forwarded from the
                                                               ; caller;
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.+++++.-----.....
>>>.<<<
>[-]+,
>>>>>>>>[-],
<<<<<<<<<,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
                                                               ; THE PLAINTEXT ITSELF to end of input;  This forward
                                                               ; is driven by the STATUS of each read rather than by a
                                                               ; count because the caller's plaintext length is the
                                                               ; caller's business: the routine was told how many
                                                               ; bytes to expect two frames ago and this program does
                                                               ; not need to know; cell 2 is the continue flag
>>+
[
<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
                                                               ; an END is the end of the caller's input: clear the
                                                               ; status the continue flag and the branch flag
[[-]>[-]>>[-]<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.+++++.-----.....
>>>.<<<
>[-]+,
>>>>>>>>[-],
<<<<<<<<<,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>[-]
]
<<
]
<<
[-]++++++++++++.--------.----.+++++.-----...                   ; close handle 5 so the routine sees end of input and
                                                               ; starts work
,,,
                                                               ; THE SEALED FRAME back out to the broker's stdout;
                                                               ; The first read here is where the routine's work is
                                                               ; waited on: a primitive that reads all of its input
                                                               ; before computing writes nothing until it has
                                                               ; finished;
>>+
[
<<
[-]++++++++++.--.--------.++++++.------...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>[-]>>[-]<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++.--.....                         ; write  op 0b handle 2 __ the broker's stdout __ flags
                                                               ; 0 one byte
>>>.<<<
>[-]+,
>>>>>>>>[-],
<<<<<<<<<,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>[-]
]
<<
]
<<
                                                               ; wait  op 10 handle 8 flags 0 __ blocking;  The reply
                                                               ; is status two length bytes then state{1} code{1}
                                                               ; signal{1} reserved{1};
;
                                                               ; THE ROUTINE'S EXIT CODE BECOMES THIS PROGRAM'S; Ask
                                                               ; for a routine that is not there and the interpreter
                                                               ; cannot exec it the child exits 127 and this program
                                                               ; exits non_zero rather than reporting success with no
                                                               ; output;
[-]++++++++++++++++.----------.------.++++++++.--------.....
,,,,
>>>,<<<                                                        ; cell 3 takes the code
,,
[-]++++++++++++.--------.----.++++++.------...                 ; close the pipe end and the process handle
,,,
[-]++++++++++++.--------.----.++++++++.--------...
,,,
[-]++.-.-.                                                     ; exit  op 02 len 1 and the code is the routine's own
>>>.<<<
,,,
