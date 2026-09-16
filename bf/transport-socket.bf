; transport_socket_poke __ seal a BMX transport frame and send it over TCP;
;
; STEP ONE OF THE ROAD TO FULL INTEROPERABILITY and the one that needs no new
; cryptography at all; bf/transport_frame_poke proves a brainfuck program can
; compute the same sealed frame the Java reference computes; This proves it can
; put that frame ON A WIRE which is the difference between agreeing with a
; file and talking to something;
;
; IT TALKS TO ITSELF deliberately and that is not as weak as it sounds; The
; program binds an ephemeral port listens connects to it accepts the
; connection seals a frame through bfsodium's ChaCha20_Poly1305 writes the
; ciphertext to the socket reads it back off the accepted end and hands it to
; the broker's stdout; Every byte of that crosses a real kernel socket;
;
; What it does NOT yet prove is agreement with a peer in another language;
; That needs a BMX handshake and therefore X25519 and ML_KEM __ steps 3 and 4
; of the road in this directory's README; This is step 1 and step 1 is the
; one that turns "computes the same bytes" into "sent bytes to something";
;
; NO PORT IS AGREED OUT OF BAND because brainstem's bind REPLIES WITH THE
; ADDRESS IT ACTUALLY BOUND; There is no getsockname op so that reply is the
; only way a program can learn the port it was given and this file reads those
; two bytes out of the reply and emits them straight back in the connect frame;
; It is the same design brainstem's own bf/net/loopback uses and it is why
; this needs no second process and no coordination;
;
; THE EXPECTED OUTPUT IS transport_frame_poke's BYTE FOR BYTE; The same key
; sequence number and plaintext seal to the same ciphertext so the frozen
; vector checks the socket path with no second expectation to maintain: a
; stronger claim against the same number;
;
; IO  in:  key{32}  seq{8} LE  plen{1}  pt{plen}
; out: ciphertext{plen}  tag{16} having gone out through one socket end
; and come back in through the other
;
; The plaintext length is ONE byte here rather than the two transport_frame
; takes because the read back off the socket is a counted loop and its count
; is derived: plen  plus  16 has to fit a cell so plen is at most 239;
;
; NOTHING IS EVER CLOSED so every handle in this file is a literal; brainstem
; bumps a slot's generation on CLOSE and a bfsodium primitive reads an exact
; known byte count rather than relying on end of input __ so no routine here
; needs its pipe closed to know it is finished and the sockets are reclaimed
; by the broker when the program exits;
;
; TAPE MAP
; cell 0 is the working cell: every EMIT and every READ uses it;
; cell 1 holds the status byte of a read;
; cell 3 holds one byte in flight;
; cell 4 is the branch flag: set before a read cleared by an END status;
; cell 5 counts a pump down to nothing;
; cells 7 and 8 both hold the plaintext length; cell 8 survives the pump so
; that plen  plus  16 can be derived from it twice;
; cell 9 holds a reply's declared payload length while it is drained;
; cells 13 and 14 hold the port bind gave us little endian as it arrives;
;
; Frames transcribed by hand from brainstem's ABI_md sections 3 6 7_5 to
; 7_11 and 7_14 to 7_16;
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
; ============================================================ ; the listening socket
[-]+++++.--.---.+..-.                                          ; socket  op 05 domain 1 IPv4 type 1 stream protocol 0;
                                                               ; Handle 4;
,,,,,,,
                                                               ; bind  op 07 handle 4 flags 1 REUSEADDR then the 32
                                                               ; byte address: family 01 reserved 00 port 0000 meaning
                                                               ; "any" then 127_0_0_1 in READING ORDER and twenty four
                                                               ; zero bytes; Those zeros cost nothing to
; emit and buy a constant offset;
[-]+++++++.+++++++++++++++++++++++++++++++.-----------------
  ---------------------.++++.----...+.-.                       ; continued
+.-...++++++++++++++++++++++++++++++++++++++++++++++++++++++
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  +++++++++++++++.------------------------------------------   ; continued
  ----------------------------------------------------------   ; continued
  ---------------------------..+.                              ; continued
-............
............
                                                               ; the reply is status two length bytes then the address
                                                               ; actually bound; Drain the status the length the
                                                               ; family and the reserved byte: five;
,,,,,
                                                               ; THE PORT into cells 13 and 14 little endian as it
                                                               ; lies; This is the whole reason no port has to be
                                                               ; agreed in advance;
>>>>>>>>>>>>>
,
>,
<<<<<<<<<<<<<<
,,,,,,,,,,,,,,,,,,,,,,,,,,,,                                   ; and the remaining twenty eight bytes of the address
                                                               ; record
[-]++++++++.--.------.++++.----.....                           ; listen  op 08 handle 4 backlog 0 meaning 128
,,,
[-]+++++.--.---.+..-.                                          ; socket  op 05 again;  Handle 5 the client end;
,,,,,,,
[-]++++++.++++++++++++++++++++++++++++++++.-----------------   ; connect  op 06 handle 5 flags 0 family 01 reserved 00
  ---------------------.+++++.-----.....+.-.                   ; ;;;
>>>>>>>>>>>>>                                                  ; ;;; then the port this program was given out of cells
                                                               ; 13 and 14 ;;;
.
>.
<<<<<<<<<<<<<<
[-]+++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; ;;; then 127_0_0_1 and twenty four zeros;
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  ++++++++++++.---------------------------------------------   ; continued
  ----------------------------------------------------------   ; continued
  ------------------------..+.                                 ; continued
-............
............
,,,
                                                               ; accept  op 09 handle 4 flags 0;  The reply is a
                                                               ; handle and the peer address: 3 header  plus  4  plus
                                                               ; 32 = 39 bytes;  Handle 6 the accepted end;
[-]+++++++++.---.------.++++.----.....
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
; ============================================================ ; the sealing routine
[-]++++++++++++++.------------.--...                           ; pipe  op 0e;  Handles 7 (read) and 8 (write);
,,,,,,,,,,,
[-]++++++++++++++.------------.--...                           ; pipe again;  Handles 9 (read) and 10 (write);
,,,,,,,,,,,
[-]+++++++++++++++.+++++++++++++++++++++++++++++++++.-------   ; spawn chacha20poly1305_bf;  len 0x30 = 48;  Proc 11;
  -----------------------------------------.-....+..++..--..   ; continued
.+++++++.-------...
+.+++++++++.----------...
..
+++.---.++++++++++++++++++++++++++++++++++++++++++++++++++++
  ++++++++++++++++++++++++++++++++++++++++++++++.++++.+++.     ; continued
------------------------------------------------------------
  --------------------------.-------------------.+++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  ++++++++++++++++++++++++++++++.+++++.-------.++.+++++.----   ; continued
  ---.-----------------------------------------------.--.+++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  +++.-.---.+++++++++++++.----------------------------------   ; continued
  --------------------------------------.++.---.+++++.------   ; continued
  -.++++++++++++++++++++++++++++++++++++++++++++++++++++.+++   ; continued
  +.                                                           ; continued
,,,,,,,
>>>>>                                                          ; THE KEY thirty two bytes forwarded from the caller to
                                                               ; the routine
[-]++++++++++++++++++++++++++++++++
<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++++++++.--------.....
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
                                                               ; THE NONCE PREFIX: four zero bytes in one frame rather
                                                               ; than four; The caller never sent these and the AEAD
                                                               ; requires them;
[-]+++++++++++.-.----------.++++++++.--------.........
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; THE SEQ eight bytes as the caller sent them: little
                                                               ; endian is already the order the nonce wants so there
                                                               ; is no swap here;
>>>>>
[-]++++++++
<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++++++++.--------.....
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
                                                               ; THE AAD LENGTH: zero; A BMX transport frame
                                                               ; authenticates no additional data because the sequence
                                                               ; number is carried in the nonce rather than in the
                                                               ; AAD;
[-]+++++++++++.---.--------.++++++++.--------.......
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]++++++++++.--.--------.+.-...+.-...                         ; the plaintext length from the caller kept in two
                                                               ; cells
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]<<<]
>>>
[
>>>[-],
<<<
[-]
]
<<<<
>>>>>
[-]
>>>
[-]
>>>
[-]
<<<<
[-<<+>>>+>>>+<<<<]
>>>>
[-<<<<+>>>>]
<<<<<<<<<<<
[-]+++++++++++.---.--------.++++++++.--------.....             ; and sent on as the two bytes the routine wants
>>>>>>>
.
<<<<<<<
[-].
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>                                                          ; then the plaintext itself a byte at a time
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++++++++.--------.....
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
; ============================================================ ; the sealed frame goes OUT through the socket
                                                               ; plen  plus  16 bytes read off the routine and written
                                                               ; straight to handle 5 the connected client end;
                                                               ; Nothing is stored on the tape: the socket is the
                                                               ; buffer;
>>>>>
[-]
>>>
[-<<<+>>>>>>+<<<]
>>>
[-<<<+>>>]
<<<<<<
++++++++++++++++
<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.+++++++++.---------...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.+++++.-----.....
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
; ============================================================ ; and comes back IN through the other end
                                                               ; the same count again off handle 6 __ the end accept
                                                               ; gave us __ and out to the broker stdout; If the two
                                                               ; ever differed the frozen vector would say so;
>>>>>
[-]
>>>
[-<<<+>>>>>>+<<<]
>>>
[-<<<+>>>]
<<<<<<
++++++++++++++++
<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.++++++.------...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++.--.....
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
                                                               ; wait  op 10 handle 11 flags 0 __ blocking; The exit
                                                               ; code is the routine own so a routine that could not
                                                               ; be executed fails loudly rather than reporting
                                                               ; success having sealed nothing;
[-]++++++++++++++++.----------.------.+++++++++++.----------
  -.....                                                       ; continued
,,,,
>>>,<<<
,,
[-]++.-.-.                                                     ; exit  op 02 len 1 and the code is the routine own
>>>.<<<
,,,
