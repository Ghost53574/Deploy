#!/bin/bash
TIMESTAMP="$(date +%s)"
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m'

function echo_info ( ) {
    echo -n -e "${GREEN} ${1} ${NC}"
}

function echo_warn ( ) {
    echo -n -e "${YELLOW} ${1} ${NC}"
}

function echo_fail ( ) {
    echo -n -e "${RED} ${1} ${NC}"
}

echo_info """
noʎ ǝɹɐ ɓuıssǝɔɔɐ ɐ .s.n ʇuǝɯuɹǝʌoɓ )ɓsn( uoıʇɐɯɹoɟuı ɯǝʇsʎs )sı( ʇɐɥʇ sı pǝpıʌoɹd ɹoɟ pǝzıɹoɥʇnɐ-ɓsn ǝsn .ʎןuo
ʎq ɓuısn sıɥʇ sı ɥɔıɥʍ( sǝpnןɔuı ʎuɐ ǝɔıʌǝp pǝɥɔɐʇʇɐ oʇ sıɥʇ ,)sı noʎ ʇuǝsuoɔ oʇ ǝɥʇ ɓuıʍoןןoɟ :suoıʇıpuoɔ
ǝɥʇ- ɓsn ʎןǝuıʇnoɹ sʇdǝɔɹǝʇuı puɐ sɹoʇıuoɯ suoıʇɐɔıunɯɯoɔ uo sıɥʇ sı ɹoɟ sǝsodɹnd ,ɓuıpnןɔuı ʇnq ʇou pǝʇıɯıן ,oʇ uoıʇɐɹʇǝuǝd ,ɓuıʇsǝʇ ɔǝsɯoɔ ,ɓuıɹoʇıuoɯ ʞɹoʍʇǝu suoıʇɐɹǝdo puɐ ,ǝsuǝɟǝp ןǝuuosɹǝd ʇɔnpuoɔsıɯ ,)ɯd( ʍɐן ʇuǝɯǝɔɹoɟuǝ ,)ǝן( puɐ ǝɔuǝɓıןןǝʇuıɹǝʇunoɔ )ıɔ( .suoıʇɐɓıʇsǝʌuı
ʇɐ- ʎuɐ ,ǝɯıʇ ǝɥʇ ɓsn ʎɐɯ ʇɔǝdsuı puɐ ǝzıǝs ɐʇɐp pǝɹoʇs uo sıɥʇ .sı
suoıʇɐɔıunɯɯoɔ- ,ɓuısn ɹo ɐʇɐp pǝɹoʇs ,uo sıɥʇ sı ǝɹɐ ʇou ,ǝʇɐʌıɹd ǝɹɐ ʇɔǝɾqns oʇ ǝuıʇnoɹ ,ɓuıɹoʇıuoɯ ,uoıʇdǝɔɹǝʇuı puɐ ,ɥɔɹɐǝs puɐ ʎɐɯ ǝq pǝsoןɔsıp ɹo pǝsn ɹoɟ ʎuɐ pǝzıɹoɥʇnɐ-ɓsn .ǝsodɹnd
sıɥʇ- sı sǝpnןɔuı ʎʇıɹnɔǝs sǝɹnsɐǝɯ ,.ɓ.ǝ( uoıʇɐɔıʇuǝɥʇnɐ puɐ ssǝɔɔɐ )sןoɹʇuoɔ oʇ ʇɔǝʇoɹd ɓsn ʇou--sʇsǝɹǝʇuı ɹoɟ ɹnoʎ ןɐuosɹǝd ʇıɟǝuǝq ɹo .ʎɔɐʌıɹd
ɓuıpuɐʇsɥʇıʍʇou- ǝɥʇ ,ǝʌoqɐ ɓuısn sıɥʇ sı sǝop ʇou ǝʇnʇıʇsuoɔ ʇuǝsuoɔ oʇ ,ɯd ǝן ɹo ıɔ ǝʌıʇɐɓıʇsǝʌuı ɓuıɥɔɹɐǝs ɹo ɓuıɹoʇıuoɯ ɟo ǝɥʇ ʇuǝʇuoɔ ɟo pǝɓǝןıʌıɹd ,suoıʇɐɔıunɯɯoɔ ɹo ʞɹoʍ ,ʇɔnpoɹd pǝʇɐןǝɹ oʇ ןɐuosɹǝd uoıʇɐʇuǝsǝɹdǝɹ ɹo sǝɔıʌɹǝs ʎq ,sʎǝuɹoʇʇɐ ,sʇsıdɐɹǝɥʇoɥɔʎsd ɹo ,ʎɓɹǝןɔ puɐ ɹıǝɥʇ .sʇuɐʇsıssɐ ɥɔns suoıʇɐɔıunɯɯoɔ puɐ ʞɹoʍ ʇɔnpoɹd ǝɹɐ ǝʇɐʌıɹd puɐ .ןɐıʇuǝpıɟuoɔ ǝǝs ɹǝsn ʇuǝɯǝǝɹɓɐ ɹoɟ .sןıɐʇǝp
""" >> /etc/issue
echo_warn """
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNXK0kxddoddddxkO00KKXXXXXXNWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNXKOkxdolc::::::::::cccccllloooddxxkOKXNNWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNKOxollc:::::ccccccccccccccccccclccclllllloddkO0KNWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWX0kdlcccccllllcccclccclllllooooollooooooooooooooooodxkOKXNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNXKOxollllllooooooolooolllllllloooodddoodddddddoooddddoodxxddxkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXOxdooolooooodddddxxdoooddddoooooooddddxxdxdxxxxxxxxdddddddddxxxxxddxOXWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWN0xooodddddddddddxxddxxxdddxxkkxdddddddddxxxkkxxkkkxxxxxxxxxxxxxxxxxxxxxdxk0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXOdoodxxxxkkkxxxxxkkkkxxxxxxxxkkOkkxxdxxkkxxkkkkkkOOOOOOkkkkkkxxxxxxxxxxkkxxxxk0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNKkxddxkkOO00O00OOOOOOkkOOkxxkkkkkOOOOOkxxkkkkOOOkkkOOOOOOOOOOOOOOkkkkkxxxxxkkkkkOkk0NWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNKkxxxxxkkO0000O00OOO000OOO0OOOOO00000000OkkkOOO0000OOOOOkkkkkOOO000OOOOOOOkkkxxxkkOOOkOKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKOxxxxxdxkkOOOOOOOkkOO000OOOO00OO00KKKKKK000OO0000KKKK000000OOOOOOOOOOO000OOOOOkkxxxkkOOkk0NWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkdxxxxddxkOO00000000000KK00000000000000000KKK0KKKKKXXXXXXXXXKKKKKKKK00000000000000OOkkkxxkkkOKNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMW0xddxkxdxkOO0000KKKKKKKKKKKKKKKKKKKKKK0KKKKKKKXXXXXXXXXXXXXXXXXXXXXXXXXXKKKKKKKKKKKK000OOOkkkkxx0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNOooxxxxxxkO00000KKKKKKKKKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXNNNXXXXXXXXXXXKKKKKKK0000OOOOkkKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMNkoodxxxdxOOO000000KKKKKKXXXXXNNNXNNNNNNNNNNNNNNNNNXXXXXXNNNNNNNNNNNNNNNNNNNNXXXXXXXKKKKKKKK000000OOk0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMXxlldxxddxkOOO0000000KKKKXXXXXNNNNXXNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXKKKKKK00000OOkkKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMNkcloddddxkkOOO0000000KKKXXXXXXNNXXXXXXNNNNNNNNNNNNNNNNNNNNNNNNWWNNNNNNNNNNNNNNNNNNXXXXXXXXKKKKK00000OOkONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMNxclloddoddxkkOO0000000KKKXXXXXXXXXKKXXXNNNNNNNNNNNNNNNNNNNNWWWWWWWWWWNNNNNNNNNNNNNNNXXXXXXXXKKKK000000OkkKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMW0lclloooodxxkkOOOO0000KKKXXXXXXXXXXXXXXXNNNNNNNNNNNNNNNNNNNNNNWWWWWWWWWNNNNNNNNNNNNNXXXXXXXXXKKKK000000OOkONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMNxcclloooodxkkkOOOO00000KKKXXXXXXXXXXXXXXNNNNNNNNNNNNNNNNNNNNNNWWWWWWWWNNNNNNNNNNNNNXXXXXXXXXXKKKKK000OOOOkkKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMNd:ccloooddxxkkkkOOO0000KKKXXXXXXXXXXXXXXNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXNNXXXXXXXXXXXKKKKK0000OOOOkk0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXo:cclooooddxxkkkkOOO000KKKXXXXXXXXNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXXXXXKKK0000OOOOOkxONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMKl:cclloooodxxxkkkkOOO00KKKXXXXXXXXNNNNNNNNNNNNNNNXXXNNNNNNNNNNNNNNNNNNNXXXXXXXXXXXXXXXXXXXXXXKK00000OOOOOkxONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMM0l:ccclooooddxxxxkkkOOO00KKKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXNNNXXXXXXXXXXXXXXXXXXXXXXXXXKKKK00OOOOOOOOkONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMKl:ccclloooddddxxxxkkOOO000KKKKKKKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXKKXXXXXXXKKKKKKKK000OOOOOOOkxONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXo:cccllloooddddxxxxkkkOOO0000000KKKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXKKKKKKKKKKKKKKKKKKK0000000OOOOOOkkxONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXo:ccclllooooodddxxxxkkkOOOOO00000KKKKKKKKKXKKKKKKKKKKXXXXXXXXXXXXXXXXXXKKKKKKKKKKK00000K00000000OOOOOOOOkkxONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXo:ccccllooooodddddxxxxkkkkOOO00000000KKKKKKKKKKKKKKKKKKKXXXXXXXXXXXXXXKKKKKKKKKK0000000000000000OOOOOOOkkkxONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXo:ccllllloooooooddddxxxkkkkOOO000000000000KKKKKKKKKKKKKKKXXXXXXXXXKKKKKKKKKK0000000OOO0000000000OOOOOOkkkxx0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXo:cllllllooooooooddddxxxxkkkkOOOOOOO00000000000000KKKKKKKKKKKKKKKKK00000000000000OOOOO0000000000OOOOOkkkkxx0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXd:ccllllllooooooooodddxxxxxxkkkkkkkkOOOOOO00000000KKKKKKKKKK000000000OOO000000000OO00000KKKK0000OOOOkkkkxxxKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXd:cccllllllllllooooooddddxxxxxxxxxkkkkkkOOOOOO0000KKKK000000OOOOOOOOOkkOOOOOOOO0000KKKKKKKK0000OOOOOkkkxxxkKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMKo:cccllllllllllloooooddddxxxxxxxxxxxxxkkkkkOOOOOO00000000OOOkkkkkkkkkxxxkkkkOOO00KKXXKKK00OOOOkkkkkkkkkkxxkKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXo:ccllllllllllllooooodddxxxkkkkkkkkkkkkOOOkOOOOOOO00OOOOkkkkxxxxxxxxxxxxxxxxxkkOOOOOOOkkxxdddddddxxxkxxkxxkXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXo:ccllolllllllllooooddxxkkkOOOO0000000KKKKKKKKKK000OOkkkxxddddddddddxddddooodddddoooooollllccclllooddxxxxxONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMXo:clllooooooollooooddxxkkOOOOO000000KKKKXXXXXXXK00Okkxxxxdddodddddddddoollllllllc::::::::::ccclllllloodxxxONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMNd:cclooooooooloooooddxxkkkkkkkkkkkkkkkkkkkkkkkkkkkxxddddddddoddxxxdddoolccc::;;,,''',,,;;;;;;;:::;;;;;;:::lxOOO00KXNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMWx::clllooooooooooodddxxxkkxxxxddoolllllllllllllllllllclllooooodddddoollc:;;,,,'''''''.............................',:0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMWO:;cclllloooooooddddddoollc::;;,,''''''''''',,,,,,,,;;;:cccllloooooolc:;;,,'.........              ....   .....''....xMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMM0c;:ccllloooolc:;,,'.......           .   ...............',,,,;;;;;,'.......          .........  ......  ..   .:lcc;'xMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMNo,;:cccc:;'..                        ..........                 ..             .....  ...............  ....   .... ,OMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMWKc,;:;,,'. .;c;...     .............................                         ..............................      .l0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMWNNNN0l;;,,,,. .:c;,,.    ................................           ..         .................................   .xWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMWX0OOkkOx:,,,,,'.          ................................ .      ......         .................................   ;KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMKxdkOOkxoc,,,'',,'..      ................................ ..     .'''....      ...................................  .oWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMKocccoxxxl;,'.';;;:,    .....................................    .;:c:,'..     ................................ ..   ,0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMWk:'',,;:clc:,;;;:::.    . ............................... ..    ;odxxo:'..    ..............................  .... .oWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMNOc'''',,;cc::ccccc,   .. ..................................   'oxO000kl,..      ........................... ....  ;KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMWKl,'';:::cccooollc'  .. .................................   .cxO0KXXX0xc'      .......................... ....  'kWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWXx:,:ll:;,:odooodc.    ............................... .  .:dOKXNNNNXX0o'.    .......................  .   .. .xWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWWW0ocll:,';ldddddo;   .................................  .;d0XNNNNNNXXX0o'.    ..  ................     .. ..,kWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMWXkolc;,;lddddddd,   ................................ .,d0XNNNNWWNNXXKOc'...    ..............        ...,dXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMNOollc:lodddddxd,    ...... ............      ......,lkKKXXXXNXXKKKK0koc:,'..  .....................'ckXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMW0doooloddddxxxxc.  ...   ..  .......    ........'cxO0OOOOOO00OOOOO000Oxc,,,'................'',;cokXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKdoddodddddxxxxdc,..........................'';lkOxddddddxxxxxxdl:coxkd:;;::;;;,,,,,,,;;;:cclodxk0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkdddddddddxxxxxxdoc;,,'............'',,;;;,,:odc...';clloooc;'..':oddl:ccc::::::::ccccllllodxxkXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNOxdddddddxxxxxxxxxxdolc::;;;;;;;::::::cc:;;:oo:'...',:ccc::;;;;;cloooloooodoooooooooooooodxxkONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNOddddddddxxxxxxxxxddolc:::::::::cclloool:;;:cc:::cccllloodddolclodxxxxxxxkkkkkkkkkkkxxxxxkkkKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXkdoooddddxxxxxxxdddolcc::ccccloodddxxdolc:cclodxkkOkkkOOOOOkkxxxkkkkkkkkkOOOOOOOkkkkkkkkkkOXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWMMXOxdxxdddddddxxxxdddoollloooodxxkkkkkxxdooodxkO0KKK0O00KKK000OOOOOOOOOOOOkkkkkkkkkkkkkkkxkKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWW0doddddddddddddddddddddxxxkkkOOkkkkkkkkO00KK00OOOO00KK000000OOOOOOOOkkkkkkkkkkkkxxxx0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKdodddddddddddddddddxxxxxkkkOOOOOOOOOOO0000000000KKKK0000000OOOkkOOkkkxxxxxxxxxxdd0NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKdodddddddddddddddddxxxxkkkOOOOOOOOOOOO0000KKKKK0000000000OOOOkkkkkxxxxxxxxddddd0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKxoooooooooooooodddxxxkkkkkkkkxxxxkkkkxdolllodoc:cloxkOOOkkkkkkkkxxxxxdddddooxXWWWWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWMMMMWXxoooolllooooooddddxxxkkxxdolcccccc;,'........   ..':cllllllodxxxxxxdddoooc:cc::::::cclok0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWN0xc,,colllllllooooddddddddoc:;;:clc;'.................',;;:ccclooooddddolol;.  ..         ..':lx0XNWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkl,.    .,clllllllloooooooolllllollloddolllllllll::ccccccccclllllllllloollooxxo,.  ....            .',:lx0NWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWN0xo:.          .':clllllllllllllllloollllccllloooodxddooooolcccclllllllllllclodxkOOOx:.                       .,l0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKxc,.                .,ccccccccclclllllllcccccccccccccc::cccc:::ccclllllllllcclodxkkOOOOOxc.                      .  .c0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMNkc.                      'cccc:cccccccccccccccccc::::;;;;;;:::::ccllooollllcccclodxkkOOOOOOOx;.                     . .  .oXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMNk,.                         'cllc::ccccccccccccccccc:::::::::::cclooooolllcccccccodxkkOOO00Odc'.                        .   .;ONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMKc                             .:oolc::::::ccccllllllllcccccccccllloooolcccc:::cccldxxkkOOko:'.                            . ....lKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWO,                                .:llc:::::::::ccllllllllcclllllllllccc:::::c:ccclodxkxoc,.                                   ....'oXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMWWk'                                   .;llc::::;;;;;;::::::::ccc:::::::;:::::::::cllool:,..                                       ... .'xNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMXo.                                      .,:cccc::;;,,,,,,,,,,;;;,,;;;;;;;;;:::cc::;;'..                                             .....cKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWMXc                                           .',;:::;;,,,,,,,,,,,,,,;;;;;;;;,,''....                                                  ......'xNMWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMK:                                                .....''....''''''''''''....                                                            ......:OWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMXc                                                                                                                                         ..... .oXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWd.                                                                                                                                          .......;OWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMO.                                                                                                                                                 ..'dNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMN:                                                                                                                                                  .. .oXMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMWO.                                                                                                                                                   .. .lXMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMNl                                                                                                                           .                          ...cXMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMNc                                                                                                                                                      .. .lXMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMNl                                                                                                                                                       .. .oNMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMX:                                                                                                                                                      .... .kWMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMWd.                                                                                                                                                       .....,kWMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMO'                                                                                                                                                        .. ....lKWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMXc                                                                                                                                                           ......,xNMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMXc.                                                                                                                                                             ......:OWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMNo.                                                                                                                                                              ........cKWMMMMMMMMMMMMMMMM
MMMMMMMMMMMMO.                                                                                                                                                                ...  .. ;KMMMMMMMMMMMMMMMM
MMMMMMMMMMMMx.                                                                                                                                                                  . ... .dWMMMMMMMMMMMMMMM
MMMMMMMMMMMNl                                                                                                                                                                         .dWMMMMMMMMMMMMMMM
MMMMMMMMMMMK,                                                                                                                                                                       . .dXWMMMMMMMMMMMMMM
MMMMMMMMMMM0,                                                                                                                                                                        .:kO0NMMMMMMMMMMMMM
MMMMMMMMMMNOc.                                                              BLUE TEAM SAYS HI                                                                                       .:kOkkOXWWMMMMMMMMMM
MMMMMMMMMW0doo:.                                                                                                                                                                   .ckOkOkkk0NWMMMMMMMMM
MMMMMMMMMXxloodo:'.                                                                                                                                                              .;dOOkkOkkkkOXWMMMMMMMM
MMMMMMMMXklcllloooc;'..                                                                                                                                                        .'lkOOOOOkOOkkkk0WMMMMMMM
MMMMMWWXOxxdollcllollc;,,'.......                                                                                                                                            .,lxkkkOOOOkkOOOkkk0NMMMMMM
MMMMWXOkkOOOOkxdolllllcc:;;,,'....                                                                                                                                        .':ldxxxxkkkkkkkkkkkkkk0NMMMMM
MMMWKkkOOO00OOOOkxdolcccc:;;,'....                                                                                                                                    ..,;cloddxxxxxxxdddxxxkkkkkk0NWMMM
MMWKkxkOO00000OOOkkxdlc:::;;,'....                                       .                                                                                   .......',;:cclooddddddoodxxkOO0000OOOk0NWMM
MMKxxkOO000000OOOkkxddoc:;,,''...                                                                                                                            ...''',;::ccllooooooodxkOO0000000000OOkOXWM
MNOxkOO0000K000OOOkxxdollc;,.....                                                                                                                         ;c. ..'',,;::cclllllodxkOOOO00000000000OOkkOXM
W0xkOO00KKKKK000OOkkxddllc:;,...                                                                                                                          cKl....'',;::cccclodxxkkkOO0000KKKK0000OOOkx0N
XkxkOO00KKKKKK00OOOkxdollc:;'....                                                                                                                         ;KK:...'',,;;;;:loddxxkkOO000KKKKKKK0000OOkkkX
0xkOO000KKKKKKK0OOOkxdolcc:,'.....                                                                                                                        .lKKc...',,,';cloodxxkkOO0000KKKKKKK0000OOOkx0
kxkO00KKKKKKKKK0OOkkxdolcc;,'.....                                                                                                                         .kW0;...''',:lloddxxkkOOO00KKKKKKK00000OOOkxO
""" >> /etc/issue

echo_info """
noʎ ǝɹɐ ɓuıssǝɔɔɐ ɐ .s.n ʇuǝɯuɹǝʌoɓ )ɓsn( uoıʇɐɯɹoɟuı ɯǝʇsʎs )sı( ʇɐɥʇ sı pǝpıʌoɹd ɹoɟ pǝzıɹoɥʇnɐ-ɓsn ǝsn .ʎןuo
ʎq ɓuısn sıɥʇ sı ɥɔıɥʍ( sǝpnןɔuı ʎuɐ ǝɔıʌǝp pǝɥɔɐʇʇɐ oʇ sıɥʇ ,)sı noʎ ʇuǝsuoɔ oʇ ǝɥʇ ɓuıʍoןןoɟ :suoıʇıpuoɔ
ǝɥʇ- ɓsn ʎןǝuıʇnoɹ sʇdǝɔɹǝʇuı puɐ sɹoʇıuoɯ suoıʇɐɔıunɯɯoɔ uo sıɥʇ sı ɹoɟ sǝsodɹnd ,ɓuıpnןɔuı ʇnq ʇou pǝʇıɯıן ,oʇ uoıʇɐɹʇǝuǝd ,ɓuıʇsǝʇ ɔǝsɯoɔ ,ɓuıɹoʇıuoɯ ʞɹoʍʇǝu suoıʇɐɹǝdo puɐ ,ǝsuǝɟǝp ןǝuuosɹǝd ʇɔnpuoɔsıɯ ,)ɯd( ʍɐן ʇuǝɯǝɔɹoɟuǝ ,)ǝן( puɐ ǝɔuǝɓıןןǝʇuıɹǝʇunoɔ )ıɔ( .suoıʇɐɓıʇsǝʌuı
ʇɐ- ʎuɐ ,ǝɯıʇ ǝɥʇ ɓsn ʎɐɯ ʇɔǝdsuı puɐ ǝzıǝs ɐʇɐp pǝɹoʇs uo sıɥʇ .sı
suoıʇɐɔıunɯɯoɔ- ,ɓuısn ɹo ɐʇɐp pǝɹoʇs ,uo sıɥʇ sı ǝɹɐ ʇou ,ǝʇɐʌıɹd ǝɹɐ ʇɔǝɾqns oʇ ǝuıʇnoɹ ,ɓuıɹoʇıuoɯ ,uoıʇdǝɔɹǝʇuı puɐ ,ɥɔɹɐǝs puɐ ʎɐɯ ǝq pǝsoןɔsıp ɹo pǝsn ɹoɟ ʎuɐ pǝzıɹoɥʇnɐ-ɓsn .ǝsodɹnd
sıɥʇ- sı sǝpnןɔuı ʎʇıɹnɔǝs sǝɹnsɐǝɯ ,.ɓ.ǝ( uoıʇɐɔıʇuǝɥʇnɐ puɐ ssǝɔɔɐ )sןoɹʇuoɔ oʇ ʇɔǝʇoɹd ɓsn ʇou--sʇsǝɹǝʇuı ɹoɟ ɹnoʎ ןɐuosɹǝd ʇıɟǝuǝq ɹo .ʎɔɐʌıɹd
ɓuıpuɐʇsɥʇıʍʇou- ǝɥʇ ,ǝʌoqɐ ɓuısn sıɥʇ sı sǝop ʇou ǝʇnʇıʇsuoɔ ʇuǝsuoɔ oʇ ,ɯd ǝן ɹo ıɔ ǝʌıʇɐɓıʇsǝʌuı ɓuıɥɔɹɐǝs ɹo ɓuıɹoʇıuoɯ ɟo ǝɥʇ ʇuǝʇuoɔ ɟo pǝɓǝןıʌıɹd ,suoıʇɐɔıunɯɯoɔ ɹo ʞɹoʍ ,ʇɔnpoɹd pǝʇɐןǝɹ oʇ ןɐuosɹǝd uoıʇɐʇuǝsǝɹdǝɹ ɹo sǝɔıʌɹǝs ʎq ,sʎǝuɹoʇʇɐ ,sʇsıdɐɹǝɥʇoɥɔʎsd ɹo ,ʎɓɹǝןɔ puɐ ɹıǝɥʇ .sʇuɐʇsıssɐ ɥɔns suoıʇɐɔıunɯɯoɔ puɐ ʞɹoʍ ʇɔnpoɹd ǝɹɐ ǝʇɐʌıɹd puɐ .ןɐıʇuǝpıɟuoɔ ǝǝs ɹǝsn ʇuǝɯǝǝɹɓɐ ɹoɟ .sןıɐʇǝp
""" >> /etc/issue
systemctl restart ssh.service
