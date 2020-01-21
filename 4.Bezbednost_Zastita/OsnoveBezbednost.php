
MOJE: Da li bi mogao da provucem HACK preko mojih cookies

#Bezbednost web aplikacije
#Forumski uvod(Duplirano)
    #Zaštita ULAZNIH tačaka Aplikacije(formi) 

    #Hešovanje (Hashing) lozinki:
    #Hešovanje lozinki pomoću password_hash:
        #password_hash() Metoda
    
    #Filtriranje:
        #Validacija/Sanacija:
            #Validacija
                #filter_var()
                #filter_var_array()
                #fliter_input()
                #filter_input_array()
                #filter_has_var()      =
                #ctype_alnum()  
                #ctype_alpha()
                #ctype_digit
                #ctype_lower, ctype_upper 
                #filter_list()
                #is_numeric():

            #Sanacija(sanitization):
            #Regex 
                #preq_match('ovotrazi', $string),
                #preg_match_all()
                #preg_replace()
      
    
    #OPASNOSTI NeFiltriranja::
        #Cross-Site Scripting (XSS) + strip_tags(),htmlentities(),htmlspecialchars()
        #Pristup iz Komandne Linije:
        #Input Fajlova
   
    
    #Konfiguracioni fajlovi
        #safe_mode:
        #disable_functions<BR/>
        #Register Globals:<BR/>
        #url_fopena
        #max_memory:
        
    #Register Globals:
    #PRIKAZ GREŠAKA Bezbedosnoni Rizici:
        #PRIKAZ GREŠAKA prilikom RAZVOJA APLIKACIJE
        #PRIKAZ GREŠAKA Produkciono (live) okruženje
    

<div>
    <!-- 
    https://phpsrbija.github.io/php-the-right-way/#dependency_injection
    https://www.link-elearning.com/site/kursevi/lekcija/6139
    http://www.link-elearning.com/lekcija-Bezbednost-veb-formi_6139
    http://phpsrbija.github.io/php-the-right-way/#data_filtering
    -->
    #Bezbednost web aplikacije
    <p>
        Postoje loši ljudi koji žele i spremni su da naude vašoj web aplikaciji. 
    </p>
    
    <P>
        Nemojte nikad imati poverenja u tuđi unos ubačen u vaš PHP kod. 
        <br/>
        Uvek očisitite i overite tuđi unos pre nego što ga iskoristite u kodu. 
        <br/>
        Strani unos može biti svašta: 
        <br/>
        -$_GET i $_POST unešeni podaci iz forme<br/> 
        -Serverske globalne promenljive<br/>
        - body HTTP zahteva preko fopen('php://input', 'r')(ONO KADA UVODIMO CELU tudju STRANICU/SCRIPTU U NAS PROJEKAT). <br/>
    </P>
    
    <p>
        Važno je da vi preduzmete neophodne mere predostrožnosti kako bi poboljšali sigurnost vaše aplikacije.
        Srećom, dobri ljudi iz The Open Web Application Security Project (OWASP) su sastavili obimnu listu poznatih sigurnosnih propusta i metoda kako da se zaštite od njih. 
        Ovo je obavezno štivo za svakog developera kome je stalo do bezbednosti.
        <br/>
        https://www.owasp.org/index.php/Main_Page
        <br/>
        https://www.owasp.org/index.php/Guide_Table_of_Contents
    </p>
</div>

<div>
        #Forumski uvod(Duplirano)
        <p>
            Prvi i osnovni korak svakog php web developera je instalirati na svoje vlastito računalo lokalni web server i podršku za php.
            <BR/>
            Sam postupak je nadasve jednostavan, a na webu se lako mogu pronaći “all in one” paketi instalacije Apache/php/Mysql-a.
            <BR/>
            Nakon lokalne instalacije slijedi razvoj željene aplikacije te nakon toga deployment na server. 
            <BR/>
              U nastavku pročitajte kako riješiti nekoliko najčešćih problema uzrokovanih razlikama u lokalnoj i serverskoj instalaciji te postavkama php-a:
        </p>
        <p>
            U oko 90% autoinstalera za lokalne potrebe (poput Wamp ili xampp paketa) imaju u sebi uključene defaultne postavke 
            i uglavnom su uključeni svi mogući dodatni moduli i extenzije.
            <br/>
            Na serveru s druge strane treba pripaziti na sigurnost web stranica i ostalih korisnika servera, te potrošnje resursa. 
            U skladu sa time instalacija php-a na serveru neće imati u sebi uključene sve dostupne php module/extenzije niti će imati podešene defaultne konfiguracijske parametre.
            <br/>
            U zadnjih nekoliko godina najčešći problemi na koje korisnici shared hostinga nailaze su problemi s postavkama
            <BR/>
            link ka #Konfiguracioni fajlovi
          
        </p>
        <!-- 
        
        Vladan Stavrić edited a doc. OVDE JE OBJASNJAVAO kako zastiti aplikaciju koja ima ULAZNE i IZLAZNE metde _POST_ GET...
 *  TJ. koje opasnosti vrebaju po SERVER!!! Kako sa ulaze tako i sa izlazne strane.
    Takodje i kako zastititi DB
May 4 at 11:19am
Razumevanje php bezbednosnog koncepta
    Web sajtovi se sastoje od klijentskih i serverskih strana.
        Sve dok se sajt konzumira na klijentskoj strani, bezbedan je, jer nema nikakve veze sa serverom. 
        U trenutku kada korisnik krene u neki proces na serveru sajt postaje ranjiv. 
        Iz razloga jer počinje serverska komunikacija. Ovde obično uzimamo APACHE i MYSQL server.

    Šta se dogadja u trenutku ispisa jedne HTML stranice.
        Klijent šalje zahtev web serveru, a web server odgovara tako što šalje HTML dokument. 
        U ovom procesu nema prostora ni za šta, osim za pomenutu aktivnosti. 
        Te ovde nema bojazni za narušavanje bezbednosti.
            U ovom procesu postoji još nekoliko koraka.

            Prvi korak je zahtev (REQUEST)
            npr: http://php.net/manual/en/httprequest.send.php

            Prvi korak šalje serveru zahtev za HTML dokument, ali, server, umesto da pronađe i prosledi taj dokument, on prosleđuje serverskoj skripti ceo zahtev.
            Serverska strana obradjuje ceo zahtev i onda ga šalje klijentskoj strani. Ova obrada je ključna tačka za bezbednost jedne Web aplikacije!
            Ukoliko korisnik uspe da infiltrira svoj deo koda u serversku skriptu, imaće "neograničene" mogućnosti za manipulaciju serverom.

            Sad možemo zaključiti da je aplikacija ranjiva pri "ULAZU". Zbog toga je i najbitnije da budemo sigurni u to, šta u nju ulazi.
            Ovde nam je jedina opcija da kontrolišemo ULAZ!

                Šta je ULAZ u Web aplikaciju?
                Da bi korisnik mogao da pristupi do serverskog koda neke aplikacije, 
                kroz HTML dokument koji je vidljiv, potrebno je da pošalje neki PARAMETAR serveru.
                Parametri dolaze do aplikacije kroz forme tipa POST ili URL string GET.

                    Kao promenljiva (vrednost - varijabla) mogu da izgledaju ovako:
                    $_POST['ime promenljive'] - $_GET['ime promenljive'] 
                    npr: GET parametar -> http://stackoverflow.com/questions/13427177/php-get-url-with-parameter

                    Kada neki od ovih parametara dođe do servera, server ga smešta u odgovarajuću promenljivu. 
                    Ove promenljive su jedinstvene, a tako su i dostupne celoj aplikaciji bez obzira na veličinu. 
                    Zato se nazivaju superglobalne promenljive.


                        Superglobalne koje se najčešće koriste prelaze put od klijenta do servera i obrnuto.
                        U tom putu one mogu da dodju kao opasnost po server, sa tim u vezi potrebna je posebna obrada kako bi njihova upotreba bila bezbedna.
                            Neki od primera koji su potrebni da bu ušli u osnove su:
                                Crne i bele liste
                                Ovde će biti reči o filtraciji podataka. Belo asocira na nešto dobro, a crno na nešto loše.

                            Kada filtriramo podatke, aplikaciji dajemo odredjene naredbe.
                                -puštaj onog kome dozvolim
                                -ne puštaj onog kome ne dozvolim

                                Odnosi se na administratora aplikacije u ovom primeru, tj. vi kao programer želite to da uradite.
                                Ova dva pojma zabrane - dopusta naziva se crno bela lista.
                                Razlika izmedju ove dve liste je u tome što bela lista ima veću frekvenciju, a crna manju.
                                Više ćete raditi sa dopustima, nego sa zabranama.

                                Bela lista se smatra boljim bezbednosnim konceptom od crne liste. 
                                Bela lista je ograničena samo na poznate vrednosti, te neželjene vrednosti imaju manju šanse da prodju.

                            Ulaz
                            Kao što je napomenuto superglobalna promenljiva je ULAZ. 
                            Samim tim, tu ujedno imamo i najveću kontrolu.
                            Ono što se prvo uzima je korisnik. Odakle dolazi i da li je registrovan!?
                            Lokacija sa koje je korisnik došao na našu stranu, naziva se referer.

                            Tu može proveriti odakle korisnik dolazi.
                        U našem sistemu imamo neke unete korisnike koji su se ranije registrovali.
                        To radimo putem Web formi. Forma MORA da dolazi sa sigurne lokacije.
                        A to može da bude naš server.
                        Ukoliko očekujemo da korisnik bude registrovan u sistemu, vršimo sistemsku proveru putem cookie-a, session-a ili baze.
                        Kada je korisnik proveren, sledeća tačka je sam unos.

                        U Web aplikacijama korisnik može ozbiljno da nam naudi jedino putem serverskog ili SQL skripta.
                        Takav unos najčešće potrebno je preduprediti.
                        To ćemo uraditi validiranjem sadržaja koji korisnik unosi.

   
    Izlaz:
    U PHP_u verovatno će izlaz naše aplikacije biti sam HTML dokument ili neka struktura podataka. 
    U bilo kom od ova dva slučaja HTML IZLAZ će pokazati svoje nedostatke!
        Prvi i obimniji primer je Cross Site Scripting XSS
        Klijentska (hack) skripta može naneti posledice klijentu.
        LINK: http://calebcurry.com/introduction-to-cross-site-scripting-xss/  + plus VIDEO

    Još jedan od primera može biti filtracija scripta.npr:
         Imate forum, a vaši klijenti žele da unose svoje skripte i prikazuju ih drugima. 
       Ako bi te skripte imale mogućnost da se izvrše, posledice po vašu aplikaciju bi bile velike!
        htmlspecialchars()
        htmlspecialchars_decode()

        Ovo neće zadovoljiti bezbednost te preporučujem pretragu sledećeg:

        1. http://php.net/trim
        2. mysql_real_escape_string($password));

    Najbolji način zaštite je da tačno ispitate ono od čega želite da se zaštitite!!!




Baza podataka
    Često spominjana kritična tačka jedne PHP aplikacije je i izvor podataka. Sami izvori aplikacije su baze, fajlovi.
    Kada je baza u pitanju, njena najranjivija tačka su upiti koje joj upućujemo, pa je zato bitno dobro isfiltrirati korisničke podatke pre nego što ih prosledimo bazi, da ne bi došlo do SQL injection:
        Za filtraciju možemo koristiti gore pomenute ili svoje funkcije.
        Što se tiče jednosmernih algoritama za enkodiranje tu je md5 kao i druge. 
        Odlična bezbednosna praksa.
        Šifra koja je jednom enkodirana na ovaj način, više se nikako ne može doći do nje.

    Potrebno je napomenuti da postoje alata koji generišu česte password_e i sami napadaju input polja na aplikacijama. Web BOT
    Odbrana od njih se postiže tako što se ograničava pristup formama i vremenki i brojčano.
    A password treba da bude veličine miminum 8 karaktera do 16.

        $sifra=md5("nekaSifra");

        Ovako enkodiranu šifru, ne možete se više povratiti, već samo proveriti!
        Tako što ćete proveru ponovo enkodirati:

            $sifra=md5("nekaSifra");
            if($sifra=="505fa039255a2d7262d1f1f29a549209"{ 
             // vas kod za izvršenje
            }

            Broj "505fa039255a2d7262d1f1f29a549209" je dobijen na sajtu: http://www.md5.cz/


    Fajl sistem
        Ono što znamo je, da php inkluduje (include, require, require_once) strane na aplikaciji.
        Sad se vratimo superglobalima i include kao primer:

        include = $GET_["strane"] + ".php";
        U ovom slučaju GET je niz array sa stranama koje trebaju da se inkluduju po potrebi u našu app.
        Korisnik (hack) bi mogao na osnovu URL_a (kucanjem u adress bar) da isčitava naše strane, osim ako mu mi to ne dozvolimo sa belom listom.
        Ovo znači da manipulacijom URL a mogućnost hack korisnika je moguća na više načina.
        Jedno od rešenja:

            $mojeStrane = array("mojaStrana","nedozvoljeneStrane");
            if in_array($_GET['strane'],$mojeStrane);
            include $strane + ".php";

                Mogla bih se URL štititi i na ovaj način:

            Tenarnim operatorom:

            $strane = isset($_GET["strane"]) ? GET["strane"] : "" (ili false ili 0)

            LINK koji objašnjava GET: http://www.sitepoint.com/using-the-ternary-operator/

            Dokument je napravljen za razumevanje bezbednosnog koncepta.
            Sigurnost aplikacije veliki je pojam i kao takvog,
            potrebno ga je uvek usavšavati!S
        
        -->
        
    </div>    
        <div>
            #Zaštita ULAZNIH tačaka Aplikacije(formi) 
            <!-- 
                Odlican primer Form validacije  <br/>
                http://www.formget.com/form-validation-using-php/
            -->
            
            <!-- 
             Jedna od glavnih ulaznih tačaka veb aplikacije je HTML forma. 
        Trenutak kada korisniku damo mogućnost da unese podatak u HTML formu, jeste trenutak kada smo izložili unutrašnjost aplikacije javnosti, 
        što je veoma opasan momenat u „životu” veb aplikacije. 
        Zbog toga je to i trenutak koji zahteva veliku pažnju u bezbednosnom kontekstu.
 
        Prvo pravilo je: izvršiti validaciju na klijentu. 
        I pored toga što, kao PHP programeri, radimo na serverskom delu aplikacije, ovo je nešto na šta moramo obratiti pažnju.
            Klijentska validacija se obično izvršava putem neke klijentske tehnologije u zavisnosti od tehnologije na kojoj počiva sam klijent.
            Najčešće je u pitanju JavaScript.
            Treba znati da validacija unosa na klijentu nije preterano moćno oružje protiv ozbiljnijih napada, 
            tako da je veoma verovatno da će nefiltrirani sadržaj često ipak uspeti da dođe do servera.

Preuzimanje GET i POST parametara

Sve što jedna HTML forma prosleđuje korisniku, nalazi se u GET, POST, odnosno REQUEST superglobalnoj promenljivoj. 
    Ove promenljive sadrže nefiltrirane podatke i zato je neophodno obraditi ih pre upotrebe.
        To možemo uraditi ručno, prema potrebama. Na primer pggledaj primer ciscenje_strniga_teksta
        Takodje u tom primeru imas i : 
        
        strip_tags(). Ova funkcija eliminiše tagove, ali i njihove nazive.
        htmlentities() Funkcija koja konvertuje HTML oznake u HTML kodove
        htmlspecialchars() isti efekat
 
 
 LAZNE FORME

Znamo da http server nije u stanju da prati stanje. 
    Zbog toga, nije u stanju sa sigurnošću da potvrdi ni isporučioca forme koju treba da obradi. 
    Ovo otvara vrata raznim malicioznim tehnologijama jer omogućava da se, 
    umesto sa originalne, forma pošalje sa korisnički odabrane lokacije, odnosno, sopstvenog veb servera.

Na primer, ako bismo postavili sledeću formu na sopstvenu stranu, njeni podaci bi bili prosleđeni Google pretraživaču:

    <form action="http://www.google.com/search" name=f>
        <input autocomplete="off" name=q title="Google Search" value="">
        <input name=btnG type=submit value="Google Search">
    </form>

Ali, nisu svi primeri ovako zanimljivi i bezazleni. Šta ako naš server prihvata podatke sa sledeće forme:
    <form action="mojserver.php" name="mojaForma">
        <input name="korisnickoime" type="text">
        <input name="sifra" type="text">
    </form>

Korisnik bi jednostavno mogao da napravi identičnu formu na svom serveru, 
 da promeni putanju action atributa u apsolutnu (http://www.njegovserver.com/mojserver.php) i da „bombarduje″ server različitim šiframa sve dok ne dobije adekvatan odgovor.

Na primer:

    $host="www.njegovSajt.com";
    $port = 80;
    $parametri = "korisnickoIme=administrator&sifra=$generisano";
    $response = "";
    $fp = fsockopen("www.njegovSajt.com", 80);
    fputs($fp, "POST /search HTTP/1.1\r\n");
    fputs($fp, "Host: {$host}\r\n");
    fputs($fp, "Content-type: application/x-www-form-urlencoded\r\n");
    fputs($fp, "Content-length: ". strlen($parametri) ."\r\n");
    fputs($fp, "Connection: close\r\n\r\n");
    fputs($fp, $parametri);
    while(!feof($fp))
    $response .= fgets($fp);
    fclose($fp);
    obradi($response);

    pri čemu je funkcija obradi() nedefinisana u primeru, a služi da se pregleda dobijeni rezultat.
     Kod iz primera može se vrteti u petlji, sve dok rezultat ne ispuni uslove zadate u funkciji obradi i sl.
        Na serveru uvek možemo proveriti Referrer-a prilikom obrade forme uz pomoć superglobala $_SERVER['HTTP_REFERER']. 
        U tom slučaju, forma neće moći da bude poslata ni sa jedne lokacije, osim sa one koju mi odobrimo:

            if($_SERVER['HTTP_REFERER']!="http://www.njegovsajt.com")
            die("Ne valja refferer");

    Treba obratiti pažnju da ovakva zaštita ne seže daleko. 
    Referer je nešto što šalje sam klijent kroz zaglavlje zahteva, pa je lako prevariti server lažnom informacijom. 
    Dovoljna je samo jedna dodatna linija iz primera:

        fputs($fp, "Referer: http://www.njegovsajt.com\r\n");

    Jedno od bezbednosnih rešenja kojima treba pribegavati je da se ulazni parametar proverava iz predefinisane liste, pre prosleđivanja u kritični kontekst.
        Na primer, ako iz forme stižu sledeći podaci:

            <select name="pol">
            <option>m</option>
            <option>z</option>
            </select>
    Njihova obrada u PHP-u će najverovatnije biti nešto poput:
        unesiUBazu($_POST['pol']);

    Zato što najčešće očekujemo da je ograničenje koje donosi select kontrola onemogućilo korisnika da unese nepravilnu vrednost. 
 *  Ovo jeste tačno, ako prenebregnemo činjenicu da je korisnik možda napravio svoju instancu forme i jednostavno, umesto select kontrole, napravio drugu kontrolu za pol:
        <input name="pol" type="text" />

Ovakva kontrola će i dalje prosleđivati pravilne nazive parametara serveru, jer poseduje adekvatan naziv, 
    ali će sadržaj (vrednosti) tih parametara biti bilo šta što korisnik unese u tekst boks. 
    To znači da će, ukoliko nije adekvatno obrađan pre funkcije unesiUBazu() ili u samoj funkciji, moći da dođe do greške i eventualnog kompromitovanja poverljivih podataka.

        Kada bismo predefinisali listu po sistemu bele liste, ne bi postojala šansa da korisnik pošalje na server ništa što ne želimo:

            $polovi=array("m","z");
            if(in_array($_POST['pol'],$polovi))
               unesiUBazu($_POST['pol']);

    Možda ovaj koncept deluje malo nesinhronizovano jer uvek treba da nam se poklapa niz u select kontroli sa nizom koji poredimo, 
        ali zapravo, to možemo rešiti korišćenjem jednog niza i za izgradnju kontrole i za testiranje. 
       Tada ćemo biti sigurni da su uneti podaci sinhronizovani sa poređenim:

            $polovi=array("m","z");

            echo "<select name='pol'>";
            for($i=0;$i<count($polovi);$i++)
                echo "<option>$polovi[$i]</option>";
            echo"</select>";

            if(in_array($_POST['pol'],$polovi))
                  unesiUBazu($_POST['pol']); 
 
            -->

    </div>    
<div>
    #Hešovanje (Hashing) lozinki:
    <p>
        Većina PHP aplikacija ima funkcionalnost koja podrazumeva prijavu korisnika (login),
        a Korisnička imena i lozinke najčešće se čuvaju u bazi podataka kako bi se kasnije koristile za autentifikaciju korisnika pri prijavi.
        <Br/>
        Upravo iz tih razloga veoma je važno da pravilno hešujete lozinke pre nego što ih sačuvate.
    </p>
    <p>
        NAPOMENA:
        <br/>
        Hešovanje lozinki je nepovratan, jednosmeran proces, koji se vrši nad korisničkom lozinikom.
        <br/>
        Pritom se kreira string fiksne dužine koji se ne može lako rekonstruisati.
        Ovo znači da možete da uporedite dva heša da biste utvrdili da li potiču od istog stringa,
        ali ne možete saznati vrednost izvornog stringa. 
    </p>
    <p>
        NAPOMENA:<br/>
        Ako lozinke nisu hešovane, a vašoj bazi pristupa neovlašćena osoba, svi korisnički nalozi biće kompromitovani.
    </p>
    
    <p>
        NAPOMENA:<br/>
        Lozinke takođe trebaju biti pojedinačno posoljene (salted) tako što ćete dodati proizvoljni string svakoj lozinci pre nego što je hešujete. 
        <br/>
        Ovo sprečava napade uz pomoć rečnika i upotreba “rainbow tabela” (obrnuta lista kriptografskih heševa za uobičajene lozinke).
    </p>
    <p>
        Hešovanje i soljenje (salting) su od vitalnog značaja jer korisnici često koriste iste lozinke za više servisa i kvalitet same lozinke može biti niskog nivoa.
        Srećom, u današnje vreme PHP sve ovo rešava na lak način.
    </p>

</div>

<div>
    #Hešovanje lozinki pomoću password_hash:
    <p>
        U verziji PHP 5.5 je uvedena password_hash() funkcija. 
        <br/>
        Ona trenutno koristi BCrypt, najjači algoritam koji PHP trenutno podržava.
        <br/>
        U budućnosti će biti ažurirana da bi podržala više algoritama ako bude neophodno. 
        <br/>
        Biblioteka The password_compat je napravljena kako bi pružila kompatibilnost za starije verzije (PHP >= 5.3.7).
    </p>
    <p>
        password_hash() funkcija će se za vas pobrinuti za “soljenje (salting)”. 
        <br/>
        So (salt) je sačuvana zajedno sa algoritmom i “cenom” (cost) kao jedan deo heša. 
        <br/>
        Funkcija password_verify() se koristi da izdvoji ovu informaciju kako bi proverila lozinku tako da vama nije potrebno odvojeno polje u bazi podataka da biste sačuvali vaše soli (salts).
    </p>
    
    <p>
        <!-- 
            http://us2.php.net/manual/en/function.password-hash.php
        -->
        #password_hash() Metoda:<br/>
        Dakle kao što smo spomenuli ugradjena PHP meotda password_hash : kreira hasirani password koristeci jedan od najjacih algoritama.
        <br/>
        Vraća password ili FALSE
        <br/>
        Ovaj metod je kompatabila sa metodom  crypt(). 
        <br/>
        SINTAKSA:<br/> 
        password_hash ( string $password , integer $algo [, array $options ] )<br/>
        $password -sifra koji zelimo da hasiramo<br/>
        $aglo = oznacava aloritam koji koristimo proliko hasiranja<br/>
        $options-dravjeri<br/>
   
<!--  PASSWORD_DEFAULT - Use the bcrypt algorithm (default as of PHP 5.5.0).
    Note that this constant is designed to change over time as new and stronger algorithms are added to PHP.
    For that reason, the length of the result from using this identifier can change over time. Therefore, it is recommended to store the result in a database column that can expand beyond 60 characters (255 characters would be a good choice).

    PASSWORD_BCRYPT - Use the CRYPT_BLOWFISH algorithm to create the hash. 
    This will produce a standard crypt() compatible hash using the "$2y$" identifier. The result will always be a 60 character string, or FALSE on failure.
-->
    </p>
    
    
    <p>
        Pogledati PRIMER: 0.password_hash
    </p>
</div>

<div>
    #Filtriranje:
    <p>
        NAPOMENA:
        <br/>
        Apsolutno nikada ne verujte “stranom” (korisnikovom) ulaznom podatku (input) koji se šalje u vaš PHP kôd. 
        <br/>
        Uvek obavaljate filtriranje, validaciju, sanitizaciju, odnosno šta god je potrebno za strane inpute,
        pre nego što ih upotrebimo u kodu. 
    </p>
    <p>
        NAPOMENA: Postoje brojni filteri i načini za proveru podataka , mada je najpreporučljivije koristiti neke od FILETRA za sanatizaiju i validaciju link #Validacija/Sanacija
    </p>
    <!-- 
    
     <p>
        Strani input može biti bilo šta: $_GET i $_POST podaci iz forme,
        neke vrednosti u superglobalnoj promenljivoj $_SERVER ili telo HTTP zahteva dobijen putem fopen('php://input', 'r').
        <Br/>
        Zapamtite, strani input nije ograničen samo na podatke iz forme koje je poslao korisnik. 
        Uploadovani i preuzeti fajlovi, vrednosti iz sesije, podaci iz cookie-a i podaci iz 3rd party web servisa su takođe strani input.
    </p>
    -->
    <p>
        
    </p>
</div>
        
        <div>
            #Validacija/Sanacija:
            <p>
                Postoje brojni filteri i načini za proveru podataka , mada je najpreporučljivije koristiti neke od FILETRA za sanatizaiju i validaciju link #Validacija/Sanacija
                <BR/>
                Filteri Validacije proveravaju podatke/string (validate) po postavljenim kriterijumima,
                <BR/>dok filteri Sanacije imaju obavezu da ga isprave (sanitization) ukoliko ne odgovara kriterijumima. 
            </p>
            <p>
                Sasvim je dovoljno koristiti samo validaciju, ali i ispravljanje(Sanacija) ima svoju široku primenu.
            </p>
            <div>
                #Validacija
                <p>
                     Filteri Validacije proveravaju podatke/string (validate) po postavljenim kriterijumima.
                </p>
                <p>
                    Sasvim je dovoljno koristiti samo validaciju, ali i ispravljanje(Sanacija) ima svoju široku primenu.
                    
                </p>
                <p>
                    Najčešća korišćena metoda  VALIDACIJE , odnosno Sintaksa za FILTERE Validacije je filter_var($var, $filter);  
                    <BR/>
                    I ONDA SAM POSTAVLJAS DRAJVERE.
                </p>
                <p>
                     Filteri validacije: http://php.net/filter.filters.validate
                </p>
                <p>
                    Dakle pored filter_var postoje još dosta drugih metoda:
                </p>
                <ul>
                    <li>
                        #filter_var()
                        <p>
                          SINTAKSA: 
                        filter_var ( mixed $variable [, int $filter = FILTER_DEFAULT [, mixed $options ]] )

                           $variable   = promenljiva koju filtriramo
                           $filter     - sam postavaljm ako ne zelim default...to su one ID vrednsoti iz tipova filtera ...Inace ako neista ne postavim bice default  sto je i isto kao  npr filter  FILTER_DEFAULT will be used, which is equivalent  FILTER_UNSAFE_RAW. 
                           $options    - opcioni niz...sa njim mozemo da obezbdeimo postavaljnnje FLAGS, ili pozive callbackf funkcijama
                        </p>
                        <p>
                            PRIMER:<br/>
                            Podesavanje OPTION pogledaj primer POSTAVALJNJEOption_Flags_Drajvere_ZaFiltere
                            dakle imamo niz $option koji U SEBI SADRZI CLAN :<br/>
                            1. 'option' koji u sebi sadrzi niz sa atributima  'default' => 3,  'min_range' => 0  ostali  NJIH MOZES NACI U TABELAMA TIPOVI FILTEREA POD OPTION
                            <br/>2.  'flags' => FILTER_FLAG_ALLOW_OCTAL,
                        </p>
                        <p>
                            FILTRIRAJU UNUTRASNJE PROMENLJIVE,Filtrira promenljivu sa FILTEREOM koji postavim,!
                            Mogu da očiste tekst i overe tekstualne formate.
                            <BR/>
                            Odnosno mogu se koristiti za filtriranje nekog teksta, kao i za njegovu validiciju (npr. email adrese).
                            <BR/>
                            i na taj način Validacija obezbeđuje da strani input bude u skladu sa onim što vaša aplikacija očekujete. 
                        </p>
                        <!-- 
                            NAPOMENEEE iz PHP
                            Pay attention that the function will not validate "not latin" domains.

                            if (filter_var('уникум@из.рф', FILTER_VALIDATE_EMAIL)) { 
                                echo 'VALID'; 
                            } else {
                                echo 'NOT VALID';
                            }
                            */

                            /*
                             * I found some addresses that FILTER_VALIDATE_EMAIL rejects, but RFC5321 permits:
                            foreach (array(
                                    'localpart.ending.with.dot.@example.com',
                                    '(comment)localpart@example.com',
                                    '"this is v@lid!"@example.com', 
                                    '"much.more unusual"@example.com',
                                    'postbox@com',
                                    'admin@mailserver1',
                                    '"()<>[]:,;@\\"\\\\!#$%&\'*+-/=?^_`{}| ~.a"@example.org',
                                    '" "@example.org',
                                ) as $address) {
                                echo "<p>$address is <b>".(filter_var($address, FILTER_VALIDATE_EMAIL) ? '' : 'not')." valid</b></p>";
                            }
                            ?>
                            /*

                             * And this is also a valid url 

                                http://example.com/"><script>alert(document.cookie)</script>
                             * 
                             *  */

                        -->
                        <P>NAPOMENA:<br/>
                            filter_input_array  je slicna filter_var_array po nacinu rada , dok je
                            filter_input  je slicna  filtre_var  po nacinu rada
                        </P>
                        
                    </li>
                    <li>
                        #filter_var_array()
                        <!-- 
                            http://php.net/manual/en/function.filter-var-array.php
                        -->
                        <p>
                            FILTRIRAJU UNUTRASNJE PROMENLJIVE,filtrira vise podataka u jednom cugu kroz niz,
                            sa jednim pozivom funkijimogu da očiste tekst i overe tekstualne formate (npr. imejl adrese).
                        </p>
                        <p>
                            Gets multiple variables and optionally filters them. Uzima vise promenljivih(niz) i filtrira ih bez prekidanja, znaci u jednom cugu u jedno pozivu
                            znaci samo se jednom pozove filter_var_array  i on obavi filtriranje za vsaki ulaz bez prekidanja dok ne obavi sve!
                            <br/>
                            Dok kod fliter_var  za svaku promenljivu ide po jedan poziv
                        </p>
                        <p>
                        SINTAKSA  filter_var_array ( array $data [, mixed $definition [, bool $add_empty = true ]] )
                            $definition= UNUTAR definition koa NIZ opisujes koje ces FILTRERE, FLAGS, DRAJVERE DA PRIMENIS
                            POGLEDAJ PRIMER primer_filter_var_array I BICE TI JASNO KAKO FUNKCIONISE!
                        bool $add_empty = true  =vraca null za prazne clanove, kako ne bi dolazilo do problema
                        </p>
                        <p>
                            Return Values Vraca: 
                            Ako je sve ok Vraca niz koji sadrzi filtrirane dolazne podatke sa URL u suprotnom vraca false
                            An array value will be FALSE if the filter fails, or NULL if the variable is not set.
                            Svaka vrednost niz bice FALSE, ako neki filter/flags nije isprava , ILI VRACA NULL ako promenljiva nije postavaljena zahvaljujuci $add_empty = true 
                            Or if the flag FILTER_NULL_ON_FAILURE is used, it returns FALSE if the variable is not set and NULL if the filter fails.
                            Ili ako koristimo flag FILTER_NULL_ON_FAILURE vratice FALSE ako promenljiva nije postavaljena ili vratice NULL ako je filter NEISPRAVAN!
                        </p>
                        <P>NAPOMENA:<br/>
                            filter_input_array  je slicna filter_var_array po nacinu rada , dok je
                            filter_input  je slicna  filtre_var  po nacinu rada
                        </P>
                    </li>
                    <li>
                        #fliter_input()
                        <p>
                            FILTRIRAJU PODATKE KOJI DOLAZE DIREKTNO SA URL POST GET COOKIES....
                            MEDOTAMA ,mogu da očiste tekst i overe tekstualne formate (npr. imejl adrese).   
                        </p>
                        <P>NAPOMENA:<br/>
                            filter_input_array  je slicna filter_var_array po nacinu rada , dok je
                            filter_input  je slicna  filtre_var  po nacinu rada
                        </P>
                
                        
                    </li>
                    <li>
                        #filter_input_array()
                        <P>
                            FILTRIRAJU PODATKE KOJI DOLAZE DIREKTNO SA URL POST GET COOKIES....
                            MEDOTAMA  ,mogu da očiste tekst i overe tekstualne formate (npr. imejl adrese). 
                            <bR/>
                             filter_input_array  je slicna filter_var_array po nacinu rada 
                        </P>
                        <p>
                            filter_input_array — Gets external variables and optionally filters them
                            UZIMA promenljive sa URL(external) i opciono ih filtrira. SLICNO KA filter_has_var
                            <br/>
                            Ovu funkcji treba koristiti kada dolazi veci broj vrednoti u jednom "dolasku/pozivu" kao u nizu
                            dok ako dolaze vrednsoti jedna po jedan koristi  filter_input( funkciju)
                            Dakle osnovna razlika izmedju filter_iput  i filter_input_array je sto ova prva prima po jednu vrdsnost sa URL i filtrira ,
                            dok ova druga prima vise vrednosti(kroz niz) i filtrira ih u jednom pozivu
                        </p>
                        <p>
                            SINTAKSA:<br/>  
                            filter_input_array ( int $type [, mixed $definition [, bool $add_empty = true ]] )
                            $type = One of INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, or INPUT_ENV.<br/>
                            $definition =?  POGLEDAJ  primer_filter_var_array I BICE TI JASNO KAKO FUNKCIONISE!<br/>
                            UNUTAR definition KAO NIZ opisujes koje ces FILTRERE, FLAGS, DRAJVERE DA PRIMENIS
                            add_empty =vraca null za prazne clanove, kako ne bi dolazilo do problema
                        </p>
                        <p>
                            Return Values Vraca:<br/>  
                            Ako je sve ok Vraca niz koji sadrzi filtrirane dolazne podatke sa URL u suprotnom vraca false<br/> 
                            An array value will be FALSE if the filter fails, or NULL if the variable is not set.<br/> 
                            Svaka vrednost niz bice FALSE, ako neki filter/flags nije isprava , ILI VRACA NULL ako promenljiva nije postavaljena zahvaljujuci $add_empty = true 
                            Or if the flag FILTER_NULL_ON_FAILURE is used, it returns FALSE if the variable is not set and NULL if the filter fails.
                            Ili ako koristimo flag FILTER_NULL_ON_FAILURE vratice FALSE ako promenljiva nije postavaljena ili vratice NULL ako je filter NEISPRAVAN!
                        </p>
                        
                    </li>
                    <li>
                        #filter_has_var()      =
                        <p>
                            filter_has_var Proverava da li dolazeca promenljiva sa URL odgovara odredjeno tipu ULAZA.
                            <br/>
                            Vraca true ili false .OBAVEZNO POGLEDAJ U PROJKETU!  
                        </p>
                        <p>
                            SINTAKSA :<br/>
                            bool filter_has_var ( int $type , string $variable_name )
                            <br/>
                            $type = MOGUCI TIPOVI UZLAZA --- INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, or INPUT_ENV.<br/>
                            $variable_name - promenljiva koju proveravamo  DOLAZI DIREKTNO SA URL
                        </p>
                        <p>
                            NAPOMENA MOJE: filter_has_var  <br/>                 
                            VAZNOOOO! ZNACI DOLE u napomeni i kroz primere se vidi da filter direktno svlaci promenljivu sa URL , 
                            ne mozes na nju npr: uticati/menjati unutar koda pre filtera!!!!!!
                            MOJE ZNACI NE MOZEMO MENJATI INPUT PROMENLJIVE(one koje dolaze sa URL) unutar koda , vec OVAJ FILTER UZIMA VREDNOSTI DIREKTNO SA URL
                        </p>
                        <p>
                            NAPOMENA:<br/>
                            Please note that the function does not check the live array, 
                            it actually checks the content received by php:
                            DAKLE NE PROVERA NPR: TVOJ NIZ  VEC SAMO ONAJ SADRZAJ KOJI DOLAZI DIREKTNO SA PHP
                        </p>
                        <!-- 

                            $_GET['test'] = 1;//inace ovo je niz, odnosno jedan clan niza ALI SA NJIM NISTA NE MANJAS!??!JER SE FILTER PALI DIREKTNO NA BROWSER INPUT   localhost/Greske-Error/FiltritanejPodataka/FilterFunctions/filter_has_var/index.php?test=nesto
                            print_r($_GET); //TAKO da mi nije jsano sta je ovim hteo da postigne, kada to nece ni doci do filtera vec ide ono sto je u liveu UNTAR URL
                            echo '<br/>';
                            echo filter_has_var(INPUT_GET,'test' ) ? 'Yes' : 'No';

                            //would say "No", unless the parameter was actually in the querystring.
                            //Also, if the input var is empty, it will say Yes.
                            //
                            //TA NOTIFIKACIJA MI NIJE JASNA ALI KAKO DA VIDIS DA LI FUNKCIONISE
                            //DAKLE U browseru kucaj
                                //  localhost/Greske-Error/FiltritanejPodataka/FilterFunctions/filter_has_var/index.php?test=nesto


                            echo '<br/><br/><hr>SADA PRIMER KADA SE OPET VIDI PROBLEM<BR/><hr>';
                            //KUCAJ RECIMO U URL  ?email=1  //vratice  Email Found  ako nema emai vratice false
                             if ( !filter_has_var(INPUT_GET, 'email') ) {
                                    echo "Email Not Found";
                                }else{
                                    echo "Email Found";
                                }


                            //    Consider on second example
                            echo '<br/><br/><hr>';

                            $_GET['email']="info@nanhe.in";
                            if ( !filter_has_var(INPUT_GET, 'email') ) {
                                    echo "Email Not Found";
                                }else{
                                    echo "Email Found";
                                }
                            //But output will be Email Not Found

                                //MOJE ZNACI NE MOZEMO MENJATI INPUT PROMENLJIVE unutar koda , vec OVAJ FILTER UZIMA VREDNOSTI DIREKTNO SA URL
                        -->
                    </li>
                    <li>
                        #ctype_alnum()  
                        <p>
                            Provera stringove , ako naleti na broj vraća false.
                        </p>
                    </li>
                    <li>
                        #ctype_alpha()
                        <p>
                            Provera slovnih karaktera
                        </p>
                    </li>
                    <li>
                        #ctype_digit
                        <p>
                            Provera brojnih karaktera
                        </p>
                    </li>
                    <li>
                        #ctype_lower, ctype_upper 
                        <p>
                            ctype_lower Provera malih slova<BR/>
                            ctype_upper Provera velikih slova
                        </p>
                    </li>
                    <li>
                        #filter_list()
                        <p>
                            metoda koja vraca listu svih ID filtera
                        </p>
                    </li>
                    <li>
                        #is_numeric():
                        <p>
                            Validacija brojnih vrednosti: Dakle provera da li su zaista brojne vrednost<br/>
                            Konkretno, ukoliko imamo stranicu koja na osnovu URL komande, odnosno zadatog ID parametra, 
                            ispisuje informacije o proizvodu i ukoliko nismo proverili da se zaista radi o ID parametru koji je brojčana vrednost 
                            (u najvećim slučajevima jeste), napadač lako može izazvati greške u radu aplikacije,
                            pa čak i SQL injection, odnosno izmenu samog upita za “dohvatanje” informacija o proizvodu i tako ugroziti sigurnost aplikacije.
                        </p>
                        <p>
                            Validacija ovakvog inputa, odnosno ID parametra, bi bila jednostavna.
                            Trebali bi samo da osiguramo da je uneti parametar zaista broj, a da u ostalim slučajevima prikažemo grešku, odnosno nepostojeću stranu. 
                            Za tu svrhu možemo iskoristiti is_numeric() funkciju.
                                if(!is_numeric($_GET['id'])) {
                                        // prikaži 404 stranicu
                                        }
                        </p>
                        <p>
                            Pogledaj Primer/primerOpasmogKoda.php
                        </p>
                        
                    </li>
                   

                    
                  
                    
                    
                </ul>
            </div>
            <div>
                 #Sanacija(sanitization):
                <p>
                    NAPOMENA:<br/>
                    Ako koristite PDO bound parametre, oni će biti automatski sanirani.
                </p>
                <P>
                    Filtriranje uklanja (ili escape-uje) ilegalne ili nebezbedne karaktere iz stranog input-a.
                    Na primer, trebalo bi da filtrirate strane podatake pre njihovog uključivanja u HTML ili ubacivanja u SQL upit. 
                    Ako koristite PDO bound parametre, oni će biti automatski sanirani!!!
                    Ponekad je neophodno da namerno dozvolite unos određenih HTML tagova u input-u prilikom ispisa. 
                    Ovo je donekle teško za implementirati i mnogi pribegavaju korišćenju striktnijeg formatiranja kao što je Markdown ili BBCode, iako biblioteke kao što je HTML Purifier 
                    Filteri Sanitization: http://php.net/filter.filters.sanitize
                </P>

            </div>
            <div>
                #Regex 
                <p>
                    Regularni izrazi (regular expression, regex) Se takodje mogu koriste u svrhe Validacije i sanitizacije:
                </p>
                <P>
                     U sledećoj tabeli su dati često korišćeni i par zanimljivih regularnih izraza:<br/>
                            Izraz                           Opis<br/>
                        /^[a-z]*$/                      Sva mala slova u intervalu od slova a do z<br/>
                        /^[a-zA-Z0-9]*$/                Slovni i brojni znakovi (mala i velika slova i brojevi)<br/>
                        /^[a-fA-F0-9]{32}$/             Format md5 hash vrednosti<br/>
                        /^(5[1-5][0-9]{14})*$/          Format Master kreditne kartice<br/>
                        /^(4[0-9]{12}(?:[0-9]{3})?)*$/ 	Format Visa kreditne kartice<br/>
                </P>
                <p> 
                    Najčešće su to upitanju neke od metoda:
                </p>    
                <ul>
                    <li>
                        #preq_match('ovotrazi', $string),
                        <p>
                            Obavalja "pretragu" (Izvršava regex proveru) da li u stringu postoje karakteri(delovi teksta) koje smo zadali izmednju navodnika ' ' 

                        </p>
                    </li>
                    <li>
                        #preg_match_all()
                        <p>
                            Pretražuje podatke na osnovu regex i postavlja rezultate u niz, na osnovu zadatih pravila
                        </p>
                    </li>
                    <li>
                        #preg_replace()
                        <p>
                            Pretražuje podatke na osnovu regex i pogotke zamenjuje sa drugim podacima
                        </p>
                    </li>
                </ul>    
        </div>       
        
        
        
<div>
    #OPASNOSTI NeFiltriranja:
    <ul>
       
        <li>
            #Cross-Site Scripting (XSS) + strip_tags(),htmlentities(),htmlspecialchars()
            <p>
                Nefiltrirani strani input prosleđen HTML stranici za prikaz može izvršiti HTML i JavaScript na vašem sajtu!
                <BR/>
                Ovo se naziva Cross-Site Scripting (XSS) i predstavlja vrlo opasan vid napada. 
            </p>
            <p>
                Jedan od načina da sprečite XSS napade je da filtrirate sve podatke koje je korisnik generisao pre nego što ih ispišete, 
                tako što ćete ukloniti HTML tagove pomoću strip_tags() ,
                ili escape-ovati karaktere koji imaju specijalno značenje u odgovarajuće HTML entitete pomoću htmlentities() ili htmlspecialchars() funkcija.
            </p>
        </li>
        <li>
            #Pristup iz Komandne Linije:
            <p>
                Još jedan primer je prosleđivanje opcija putem komandne linije.
                <br/>
                Ovo može biti vrlo opasno (i najčešće je loša ideja), 
                <br/>ali možete da upotrebite ugrađenu escapeshellarg() funkciju da prečistite argumente komande.
            </p>
            <p>
                
            </p>
        </li>
        <li>
            #Input Fajlova
            <p>
                Poslednji primer je prihvatanje stranog input-a sa ciljem učitavanja određenog fajla. 
                Ovo se može zloupotrebiti promenom imena fajla u putanju fajla.
            </p>
            <p>
                Na vama je da uklonite "/", "../", null bajtove i druge karaktere iz putanje fajla kako biste sprečili učitavanje skrivenih, privatnih i sistemskih fajlova.
            </p>
        </li>
    </ul>
</div>

 

    
<div>
    #Konfiguracioni fajlovi
    <p>
        Pri kreiranju konfiguracionih fajlova (init)vaše aplikacije, preporuka je da to bude u skladu sa jednom od sledećih metoda:
    </p>
    <ul>
        <li>Vaše konfiguracije treba da čuvate na mestu odakle im se ne može direktno pristupiti.</li>
        <li>Ako ipak morate da čuvate konfiguracione fajlove u document root-u, neka to budu fajlovi sa .php ekstenzijom. 
            Na taj način ćete obezbediti da, čak iako im se pristupi direktno, kroz browser, neće biti prikazani u tekstualnom formatu.</li>
        <li>Informacije u konfiguracionim fajlovima bi trebalo da se adekvatno zaštite, bilo enkripcijom ili sistemskim dozvolama za prava pristupa (grupa/korisnik).</li>
        <li>Poželjno je da budete sigurni da u vaš sistem za kontrolisanje izvornog kôda ne komitujete (commit) konfiguracione fajlove koji sadrže poverljive podatke kao što su npr. lozinke ili API tokeni.
        </li>
    </ul>
    <P>
        Dodatne opcije/mogućnosti koje možemo uraditi sa konfiguracionim fajlom su npr:
    </P>
    <ul>
        <li>
            #safe_mode:
            <BR/>
            
            <p>
                Dozvoljava pristup i čitanje samo onih fajlova koji su vlasništvo korisnika pod kojim se izvršava trenutna PHP skripta.
                Za aktivaciju i deaktivaciju ove opcije, koristi se sledeći parametar php.ini dokumenta:
                <Br/>
                ; Safe Mode<Br/> ;<Br/>safe_mode = Off
            </p>
        </li>
        <li>
            #disable_functions<BR/>
            <p>
                Ova ekstremna bezbednosna mera onemogućava aktivaciju PHP funkcija nabrojanih u listi. 
                Takođe se aktivira u php.ini fajlu:<BR/>
               disable_functions = "pack, escapeshellarg, escapeshellcmd , exec,passthru, proc_close, proc_open, shell_exec, system, set_time_lim it, ini_alter, dl,popen, parse_ini_file, show_source"

            </p>
        </li>
        
        <li>
            <div>
                #Register Globals:<BR/>
                <p>
                   NAPOMENA: Od PHP verzije 5.4.0 podešavanje register_globals je uklonjeno i više se ne može koristiti.  
                   <BR/>
                   Ovo poglavlje postoji samo kao upozorenje svima onima koji su u procesu upgrade-a legacy aplikacije.
                </p>
                <p>
                    Naime kada e uključeno, register_globals podešavanje omogućava da podaci iz nekoliko tipova promenljivih (uključujući one iz $_POST, $_GET i $_REQUEST) bude dostupno u globalnom scope-u aplikacije.
                    <BR/>
                    Ovo vrlo lako može prouzrokovati bezbednosne probleme, jer aplikacija ne može sa sigurnošću znati odakle ti podaci dolaze.
                    <BR/>
                    Na primer: $_GET['foo'] bi bilo dostupno i kao $foo, što može override-ovati promenljive koje još uvek nisu definisane. Ako koristite PHP < 5.4.0 postarajte se da je register_globals podešavanje isključeno
                </p>
                <!-- 
                  Kada je register_globals uključen, PHP sam generiše promenljive na osnovu Request parametara,
                  Na primer, ako je register_globals aktiviran i strana bude otvorena na sledeći način:
                  mojaPhpStrana.php?mojParametar=10
                  U kodu će biti generisana promenljiva $mojParametar čija će vrednost biti 10.
                  Tako da bi npr: echo $mojParametar; PRIKAZAO NA stanici 10 iako iako nigde u kodu nismo eksplicitno definisali ovu vrednost.
                  POGLEDAJ primer: PostavaljnjeRegister_globals_naON
                  MADA   KADA SAM POKUSAO u init.php da ipak stavim Register_globals na  on  nisam uspeo ni da pokrenen APACHE ni posle restart servera

                  VAZNO!!!! DAKLE PROSTO Register_globals NEMOZES KORISTITI VISE NA NOVIJIM PHP SERVERIMA i ako postavis na on unutar initPHP

                  Sada cemo ipa u primeru pokazati kakva je opasnost postojala npr:
                     if($administrator){
                             //ovo je deo koji vidi samo administrator
                                     .......
                         }
                  Tada bi napadač, bez problema mogao da prilikom otvaranja strane postavi parametar administrator na true
                  mojaPhpStrana.php?administrator=true

                  Ovaj problem se rešava jednostavno -  inicijalizacijom kritičnih promenljivih na početku strane:
                  $administrator = false;
                     if($administrator){
                         //ovo je deo koji vidi samo administrator
                             ...
                         }
                         I naravno, izbegavanjem aktivacije register_globals opcije.

                         PHP register_globals opcija je postavljena na OFF na našim serverima zbog sigurnosnih razloga. Sve moderne skripte ovih dana više ne koriste register:globals, ukoliko želite dobiti greške dok je register_globals isključen možete potražiti pomoć programera koji je napravio skriptu.
                         Moguće je omogućiti register_globals upisujući ovu liniju u .htaccess datoteku:
                             php_flag register_globals on
                             Ne preporučamo uključivanje ove funkcije pošto može uzrokovati mnoge sigurnosne probleme s vašom web stranicom.
                -->

            </div>   
        </li>
        <li>
            #url_fopena
            <p>
                 U defaultnim lokalnim instalacijama url_fopen je dozvoljen, 
                dok je na serverskim konfiguracijama zbog sigurnosnih razloga zabranjen.
                <BR/>
                Razlog je cross site skirpting i iskorištavanje propusta u nekim poznatim free cms/forum aplikacijama.
                Dozvoljenim url_fopenom malicioznom korisniku su otvorena vrata da pomoću jednog ili više poznatih sigurnosnih propusta na određenim php aplikacijama includa svoj vlastiti konfiguracijski file te pridobije kompletnu kontrolu nad hosting accountom.
                Problematiku url_fopen-a ćete najčešće primijetiti prilikom legitimnog pokušaja includanja servisnih informacija poput vremenske prognoze, tečajne liste i sl.
            </p>
            <p>
                url_fopena “Problem” se manifestira kao greška na stranici koja ukazuje na nemogućnost otvaranja remote filea.<BR/>
                Npr. imamo eksterni link ka nekoj vremenskoj prognozi  prognoza.rs
                <BR/>
                Problem može nastati i pri učitavanju lokalnog filea ukoliko se poziva preko url-a.
                <br/>
                Problem/Resenje? sakriveno...
                    <br/>
                    <!-- 
                        Iako izgleda kao najjednostavnije i najbolje riješenje, url_fopen u ovim slučajevima nije niti najbolje, niti najsigurnije, a niti pristojno rješenje.
                    Mnogi će se zapitati zašto nije pristojno?
                    Odličan primjer je tečajna lista koja se mijenja uglavnom jednom dnevno,
                    no za svakog posjetitelja koji dođe na vaš site vaša skripta s fopenom otvara konekciju prema remote serveru, downloada i procesira podatke. 
                    Vaš site s vremenom “naraste”, primate po preko 20 000 unique posjeta dnevno i svaki od tih posjetitelja prilikom svakog učitavanja vašeg site-a trigera konekciju prema remote serveru. 
                    Naravno da niste jedini s takvom skriptom nego ih ima još barem stotinjak. 
                    Možete li si zamisliti koliki nepotrebni promet remote server s kojeg informaciju kupite mora dnevno procesirati?!
                    Kako onda pametno izvesti prikupljanje informacija?
                    Idealno bi bilo downloadati servisnu informaciju s remote servera u nekom prihvatljivom intervalu (svakih 6-12h). 
                    Na taj način posjedujete svježu informaciju lokalno, a remote serveru generirate samo 2-4 posjeta i uvelike mu olakšavate posao. 
                    Ne samo da je remote serveru “lakše” već se i vaša stranica puno brže učitava jer ne mora prilikom svakog učitavanja čekati odaziv s remote servera, već sve podatke ima lokalno.
                    U slučaju kvara remote servera, vaša stranica zastaje na mjestu gdje se očekuje include remote file-a dok konekcija ne istekne. 
                    Zbog toga se vaša stranica prividno sporo učitava ili se prestane učitavati. 
                    Povremenim downloadom informacije s remote servera u slučajevima havarije remote stroja, 
                    vaša stranica i dalje radi jednako brzo sa starim servisnim podacima     
                    Kako izvesti povremeni download informacija?
                    Na linux poslužiteljima postoji odlična komanda wget koju možete postaviti u cronjob da se izvršava svakih par sati te downloada svježe stanje remote filea. Ukoliko se radi o jednom remote file-u onda je sljedeća komanda kao stvorena za vas:
                        /usr/bin/wget -q [REMOTEURL] -O /home/[USERNAME]/public_html/[LOCALFILE]
                        Naravno zamjenite polja [REMOTEURL] s željenom remote stranicom, [USERNAME] s vašim cpanel useranameom i [LOCALFILE] s imenom filea u koji želite da se sadržaj spremi. Komandu možete staviti u cronjob (kroz cpanel) s željenim intervalom.

                        Ukoliko vam je od iznimne važnosti da su podaci vrlo svježi, možete koristiti alternativu url_fopena a to je curl() funkcija. 
                    *                              Dokumentaciju možete pronaći na php.net stranici, no ukratko radi se o sljedećem:
                                    dosadašnji fopen:
                                        <?php $rezultat = fopen($url,r); ?>
                                    zamenite:
                                            <?
                                                $ch = curl_init($url);
                                                curl_setopt($ch, CURLOPT_HEADER, 0);
                                                $rezultat = curl_exec($ch);
                                                curl_close($ch);
                                            ?>
                                Dodatno se jos curl komandama može dodati i zapisivanje rezultata u lokalni file, 
                                što je uz dodatne funkcije provjera vremenskih intervala vrlo zgodna simulacija wgeta na windows serverima. 
                                Osim toga curl, za razliku od fopena, je u stanju razlučiti response servera te prije samog downloda može razaznati dali je remote file prisutan ili javlja grešku (HTTP codovi 4xx, 5xx) te se uz par logičkih provjera može obustaviti download takvog nepotpunog filea. Primjere upotrebe curl-a možete pronaći na: http://www.php.net/manual/en/ref.curl.php
                                    KOMENTARI:
                                        da, u principu curl je ok, ali sam skuzio da njegova php implementacija podosta opterecuje server sa kojeg se izvrsava, 
                                        tako da i njega sad izbjegavam u sirokom luku i koristim samo za “very light” upite. 
                                        njegova visestruka uporaba u kratkom vremenskom intervalu “zagusiti” ce server do max. ako je moguce bolje koristiti nesto trece ,,,,,

                                        Definitivno se slazem, najbolje od rijesenja bi bilo koristiti wget funkciju pod linuxom i downloadati jednom (ili vise puta dnevno) file lokalno pa vrsiti manipulacije s lokalnim fileom.
                                            Na windowsima nazalost wget nije dostupan, no moze se napraviti funkcija koja ce provjeravati timestamp lokalnog filea te nece downloadati novi ukoliko je lokalna verzija mladja od definiranog vremena (simulacija crona i wgeta).
                                            Znaci sto je vise moguce smanjiti opetovane upite na remote servere.
                -->
            </p>
       
        </li>
        <li>
            #max_memory:
            <p>
                “Problem” se manifestira u obliku greški na stranici koje ukazuju na nemogućnost alociranja dodatne memorije.
                <BR/>
                Problem nastaje uslijed neoptimiziranog koda ili unosa (uploada slike ili nekog drugog filea) kojeg php mora obraditi.
                <BR/>
                Zašto se problem javlja?
                <BR/>
                Većinom slučajeva skripte “ulete” u loop te nepotrebno zapisuju vrijednosti u varijable pritom konzumirajući velike količine cpu time-a i memorije.
                U ovom slučaju treba pronaći loop i razlog zašto skripta u loop uljeće te napraviti provjere i mehanizme zaštite od ovakvog “ponašanja”.
                <BR/>
                Dosta često uzročnik može biti i neoptimizirani kod koji npr. izvrši database query, 
                query zatim vrati 600 000 rezultata (rezultat može biti veličine i do par gb podataka, ovisno strukturi tablice i količini podataka), 
                skripta zatim sve rezultate zapiše u array i tek ih onda krene obrađivati. 
                Najčešće ovakav programski kod uredno radi neko vrijeme dok ne naraste količina podataka u samoj bazi. 
                Ovakve situacije se mogu izbjeći limitiranim step by step query-em baze podataka. 
                Npr. query 10-tak unosa, obrada podataka, query sljedečih 10 unosa itd…
                <BR/>
                Sve radi savršeno dok se ne uploada neoptimizirana slika od nekoliko Mb 
                ili dok skripta ne mora odjednom izvršiti kompleksne manipulacije na nekoliko slika odjednom. 
                Znači skripte bi trebalo optimizirati za step by step radnje, s provjerom veličine input filea, 
                pražnjenjem nepotrebnih varijabli i što je više moguće koristiti cache, a ne on-the-fyl generirati 30-tak thumbnailova po stranici.
            </p>
        </li>
    </ul>
</div>   
    
 
    
    <div>
        #PRIKAZ GREŠAKA Bezbedosnoni Rizici:
        <p>
            Naime logovanje/prikaz grešaka može biti korisno prilikom traženja problematičnih mesta u vašoj aplikaciji,
            <Br/>
            ali istovremeno može javno otkriti informacije o strukturi aplikacije.
        </p>    
        <p>
            Da biste na pravi način zaštitili vašu aplikaciju od problema koje može izazvati javno prikazivanje poruka o greškama, 
            morate posebno PODESITI SERVER u slučaju razvojnog (development) i PRODUKCIONOG (live) okruženja aplikacije.
        </p>
        #PRIKAZ GREŠAKA prilikom RAZVOJA APLIKACIJE
        <p>
            Dakle prilikom RAZVOJA APLIKACIJE , kako bi ste omogućili prikaz za svaku moguću grešku prilikom razvoja,
            postavite sledeće vrednosti u vašem php.ini fajlu:
            <BR/><BR/>
            display_errors = On<BR/>
            display_startup_errors = On<BR/>
            error_reporting = -1<BR/>
            log_errors = On<BR/>
        </p>
        
        <p>
            E_STRICT nivo je uveden u verziji 5.3.0 i nije bio deo E_ALL sve do verzije 5.4.0. (#Greške i Izuzeci (exceptions):)
            <BR/>
            Šta to tačno znači? 
            <br/>
            Apropo prikazivanja svih grešaka u verziji 5.3, to znači da morate da koristite ili -1 ili E_ALL | E_STRICT.
        </p>
        <p>
            Prijavljivanje svih grešaka po verzijama PHP-a<BR/>
            < 5.3 -1 ili E_ALL<BR/>
              5.3 -1 ili E_ALL | E_STRICT<BR/>
            > 5.3 -1 ili E_ALL<BR/>
        </p>
        <div>
            #PRIKAZ GREŠAKA Produkciono (live) okruženje
            <p>
                Da biste sakrili greške u vašem produkcionom okruženju, podesite php.ini na sledeći način:
            </p>
            <p>
                display_errors = Off<BR/>
                display_startup_errors = Off<BR/>
                error_reporting = E_ALL<BR/>
                log_errors = On<BR/>
            </p>
            <p>
                NAPOMENA:<br/>
                Sa ovim podešavanjima, greške će se i dalje upisivati u log za greške (error log), ali se neće prikazivati korisniku. 
                Za više informacija o ovim podešavanjima, proučite PHP manual
            </p>
        </div>
        
        
    </div>   
    
</div>
<?php


/* 
 

  
*/

/*TREBA JOS DA PRUCIS DA LI MOZE I KAKO DA SE PODESE FILTERI ZA SANITIZACIJU I VALIDACIJU NA init.php

 http://php.net/manual/en/filter.configuration.php
 
 *  
  */

/*
///////////////////
HAKOVANJE Napadi
http://www.mytechlogy.com/IT-blogs/7630/3-common-ways-of-hacking-you-should-protect-yourself-from/#.VVwIZrntmko
//////////////////////////////
 *  */