from Crypto.Util.number import long_to_bytes
from math import prod
from gmpy2 import invert

def recover_primes(n, treat):
    primes = []
    remaining_treat = treat
    
    for i in range(16):
        # Calculate the power for this position
        power = 0x1337 - 158 * (2 * i + 1)
        
        # The prime at this position contributes p * 2^power to treat
        # Since powers decrease rapidly (by 316 each time), the most significant bits
        # of remaining_treat must come from this prime
        
        # Recover this prime by dividing by 2^power and taking most significant bits
        p = remaining_treat >> power  # Integer division by 2^power
        
        # Verify it's a factor of n
        if n % p != 0:
            print(f"Failed at prime {i}")
            return None
            
        primes.append(p)
        
        # Subtract this prime's contribution from treat
        remaining_treat -= p << power
        
        # Update n
        n //= p
        
    return primes

def main():
    n = 352189612438784047320754903106372002809877965719588610950180565262740960705788381566578345723325074804073747981488556714699194183628557150903839852453543700776971896448650422022044960974232637963499485064773137220336653165714273408753468196975611814144214482908258123395290626550717602601895666745644709508591571302894106487383195731091217527995774179358090943421864881850666765491934935419093710096767868514339375941764521600704560564724716373816013966194185050357691082654919969371044174479415710416530800029987261822155401485231590655607419352265580910531638967882492680615189164541617995862933344817766381378089
    e = 65537
    c = 258206881010783673911167466000280032795683256029763436680006622591510588918759130811946207631182438160709738478509009433281405324151571687747659548241818716696653056289850196958534459294164815332592660911913191207071388553888518272867349215700683577256834382234245920425864363336747159543998275474563924447347966831125304800467864963035047640304142347346869249672601692570499205877959815675295744402001770941573132409180803840430795486050521073880320327660906807950574784085077258320130967850657530500427937063971092564603795987017558962071435702640860939625245936551953348307195766440430944812377541224555649965224
    treat = 33826299692206056532121791830179921422706114758529525220793629816156072250638811879097072208672826369710139141314323340868249218138311919342795011985307401396584742792889745481236951845524443087508961941376221503463082988824380033699922510231682106539670992608869544016935962884949065959780503238357140566278743227638905174072222417393094469815315554490106734525135226780778060506556705712260618278949198314874956096334168056169728142790865790971422951014918821304222834793054141263994367399532134580599152390531190762171297276760172765312401308121618180252841520149575913572694909728162718121046171285288877325684172770961191945212724710898385612559744355792868434329934323139523576332844391818557784939344717350486721127766638540535485882877859159035943771015156857329402980925114285187490669443939544936816810818576838741436984740586203271458477806641543777519866403816491051725315688742866428609979426437598677570710511190945840382014439636022928429437759136895283286032849032733562647559199731329030370747706124467405783231820767958600997324346224780651343241077542679906436580242223756092037221773830775592945310048874859407128884997997578209245473436307118716349999654085689760755615306401076081352665726896984825806048871507798497357305218710864342463697957874170367256092701115428776435510032208152373905572188998888018909750348534427300919509022067860128935908982044346555420410103019344730263483437408060519519786509311912519598116729716340850428481288557035520

    print("Recovering primes...")
    primes = recover_primes(n, treat)
    
    if not primes:
        print("Failed to recover primes")
        return
        
    print(f"Successfully recovered {len(primes)} primes!")
    
    # Calculate phi(n)
    phi = prod(p - 1 for p in primes)
    
    # Calculate private key
    d = invert(e, phi)
    
    # Decrypt
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    try:
        print("Flag:", flag.decode())
    except:
        print("Raw bytes:", flag)

if __name__ == "__main__":
    main()