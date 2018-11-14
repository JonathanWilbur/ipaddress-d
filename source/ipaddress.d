module ipaddress;
import std.exception : basicExceptionCtors;

debug
{
    import std.stdio : writefln;
}
// TODO: Create Class-A subnets, Class-B subnets, etc.
// TODO: Constructors for converting IPv4 addresses to IPv6 addresses
// TODO: opCast for converting IPv4 addresses to IPv6 addresses
// TODO: opCast for converting IPv6 addresses to IPv4 addresses
// TODO:

public class IPAddressException : Exception
{
    mixin basicExceptionCtors;
    // REVIEW: For some reason, the code below makes the linker fail.
    // pure nothrow @nogc @safe
    // this(string msg, string file = __FILE__, size_t line = __LINE__, Throwable next = null);
}

private
ubyte decimalStringToByte(string decimal)
{
    debug writefln("Decimal chars: %(%c %)", decimal);
    foreach (c; decimal)
    {
        if (c < 0x30 || c > 0x39) // 0x30 is ASCII '0', 0x39 is ASCII '9'
            throw new IPAddressException("Invalid IPv4 Address String.");
    }

    if (decimal.length == 1)
    {
        return cast(ubyte) (decimal[0] & 0xCF);
    }
    else if (decimal.length == 2)
    {
        return cast(ubyte)
        (((decimal[0] & 0xCF) * 10) + (decimal[1] & 0xCF));
    }
    else if (decimal.length == 3)
    {
        // assert(decimal[0] == '0' || decimal[0] == '1' || decimal[0] == '2');

        if (!(decimal[0] == '0' || decimal[0] == '1' || decimal[0] == '2'))
            throw new IPAddressException("Invalid IPv4 Address String.");

        return cast(ubyte)
        (((decimal[0] & 0xCF) * 100) + ((decimal[1] & 0xCF) * 10) + (decimal[2] & 0xCF));
    }
    else
    {
        assert(0, "decimalStringToByte() given an invalid string.");
    }
}

///
alias IPAddress = InternetProtocolAddress;
/// An abstract class from which both IPv4 and IPv6 addresses will inherit.
abstract class InternetProtocolAddress
{

}

///
alias IPv4Address = InternetProtocolVersion4Address;
/**
    An IPv4 Address.
*/
class InternetProtocolVersion4Address : InternetProtocolAddress
{
    public ubyte[4] bytes;
    this(ubyte[4] bytes ...)
    {
        this.bytes = bytes;
    }

    /*
        FIXME: I added the boolean to the front of this constructor, because
        there is a conflict between this(string) and this(int[] ...). I want
        to ask the forum if there is some way I can get around this problem.
    */
    this(bool shit, string address)
    {
        if (address.length > 15)
            throw new IPAddressException("Invalid IPv4 Address String.");

        ptrdiff_t[] dotIndices;
        for (int i = 0; i < address.length; i++)
        {
            if (address[i] == '.') dotIndices ~= i;
        }

        if (dotIndices.length != 3)
            throw new IPAddressException("Invalid IPv4 Address String.");

        debug writefln("Dot indices: %(%d %)", dotIndices);

        bytes ~=
        [
            decimalStringToByte(address[0 .. dotIndices[0]]),
            decimalStringToByte(address[dotIndices[0]+1 .. dotIndices[1]]),
            decimalStringToByte(address[dotIndices[1]+1 .. dotIndices[2]]),
            decimalStringToByte(address[dotIndices[2]+1 .. $])
        ];
    }

    unittest
    {
        IPv4Address ipv4 = new IPv4Address(true, "10.0.255.64");
        debug writefln("Bytes: %(%02X %)", ipv4.bytes);
        assert(ipv4.bytes == [ 0x0A, 0x00, 0xFF, 0x40 ]);
    }

}

///
alias IPv6Address = InternetProtocolVersion6Address;
/**
    An IPv6 Address.
*/
class InternetProtocolVersion6Address : InternetProtocolAddress
{
    public ubyte[16] bytes;
    this(ubyte[16] bytes ...)
    {
        this.bytes = bytes;
    }

    this(bool shit, string address)
    {
        if (address.length > 39) // Max length in characters of ipv6 address
            throw new IPAddressException("Invalid IPv6 Address String.");

        for (int i = 0; i < address.length; i++)
        {
            if (address[i] == '.') colonIndices ~= i;
        }

        if (colonIndices.length > 7)
            throw new IPAddressException("Invalid IPv6 Address String.");

        /*
            NOTE: Double-colon can only be used once in IPv6 address, so this is
            here for the purpose of policing its use in the address.
        */
        bool doubleColonFound = false;

        ptrdiff_t lastIndex = 0;
        for (int i = 0; i < address.length; i++)
        {
            if (address[i] == ':' && address[i+1] == ':')
            {
                if (!doubleColonFound)
                {
                    // Pass in the necessary number of zeroes.
                    for (size_t i = colonIndices.length; i <= 7; i++)
                    {
                        this.bytes ~= [ 0x00, 0x00 ];
                    }
                    doubleColonFound = true;
                    i++;
                }
                else
                {
                    if (colonIndices.length > 7)
                        throw new IPAddressException("Invalid IPv6 Address String.");
                }
            }
            else if (address[i] == ':')
            {
                string hextet = address[lastIndex .. i];
                while (hextet.length < 4) hextet = ('0' ~ hextet);
                this.bytes ~=
                [
                    hexToByte(hextet[0 .. 2]),
                    hexToByte(hextet[2 .. $]),
                ];
            }
        }
    }
}

///
alias IPSubnet = InternetProtocolSubnet;
/// An abstract class from which both IPv4Subnet and IPv6Subnet will inherit.
abstract class InternetProtocolSubnet
{
    abstract public @property
    size_t length();

    // alias opEquals = Object.opEquals;

    public
    bool opEquals(T : InternetProtocolSubnet)(T other)
    {
        if (this.bytes == other.bytes && this.mask == other.mask)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}

///
alias IPv4Subnet = InternetProtocolVersion4Subnet;
/**
    An IPv4 Subnet.
*/
class InternetProtocolVersion4Subnet : InternetProtocolSubnet
{
    public ubyte[4] bytes;
    public ubyte[4] mask;
    static assert(bytes.length == mask.length, "Address and mask length do not match.");

    this(ubyte[4] bytes, ubyte[4] mask)
    {
        this.bytes = bytes;
        this.mask = mask;
    }

    override public @property
    size_t length()
    {
        return this.bytes.length;
    }

    public
    bool contains(IPv4Address ip)
    {
        for (int i; i < this.length; i++)
        {
            if (this.bytes[i] != (ip.bytes[i] & this.mask[i])) return false;
        }
        return true;
    }

    public
    bool contains(IPv4Subnet subnet)
    {
        for (int i; i < this.length; i++)
        {
            if (this.bytes[i] != (subnet.bytes[i] & this.mask[i])) return false;
        }
        return true;
    }

}

///
alias IPv6Subnet = InternetProtocolVersion6Subnet;
/**
    An IPv6 Subnet.
*/
class InternetProtocolVersion6Subnet : InternetProtocolSubnet
{
    public ubyte[16] bytes;
    public ubyte[16] mask;
    static assert(bytes.length == mask.length, "Address and mask length do not match.");

    this(ubyte[16] bytes, ubyte[16] mask)
    {
        this.bytes = bytes;
        this.mask = mask;
    }

    override public @property
    size_t length()
    {
        return this.bytes.length;
    }

    public
    bool contains(IPv4Address ip)
    {
        for (int i; i < this.length; i++)
        {
            if (this.bytes[i] != (ip.bytes[i] & this.mask[i])) return false;
        }
        return true;
    }

    public
    bool contains(IPv4Subnet subnet)
    {
        for (int i; i < this.length; i++)
        {
            if (this.bytes[i] != (subnet.bytes[i] & this.mask[i])) return false;
        }
        return true;
    }
}

//REVIEW: Is there a way to make these subnets immutable instead of const?
/// Default IPv4 subnets from https://en.wikipedia.org/wiki/Reserved_IP_addresses
/**
    0.0.0.0/8
*/
const public IPv4Subnet ipv4CurrentSubnet =
new IPv4Subnet([0x00, 0x00, 0x00, 0x00], [0xFF, 0x00, 0x00, 0x00]);

/**
    10.0.0.0/8
*/
const public IPv4Subnet ipv4Local10Subnet =
new IPv4Subnet([0x0A, 0x00, 0x00, 0x00], [0xFF, 0x00, 0x00, 0x00]);

/**
    100.64.0.0/10
*/
const public IPv4Subnet ipv4ServiceProviderToSubscriberWithCarrierGradeNATSubnet =
new IPv4Subnet([0x64, 0x40, 0x00, 0x00], [0xFF, 0xC0, 0x00, 0x00]);

/**
    127.0.0.0/8
*/
const public IPv4Subnet ipv4LoopbackSubnet =
new IPv4Subnet([0x7F, 0x00, 0x00, 0x00], [0xFF, 0x00, 0x00, 0x00]);

/**
    169.254.0.0/16
*/
const public IPv4Subnet ipv4DefaultLinkLocalSubnet =
new IPv4Subnet([0xA9, 0xFE, 0x00, 0x00], [0xFF, 0xFF, 0x00, 0x00]);

/**
    172.16.0.0/12
*/
const public IPv4Subnet ipv4Local172Subnet =
new IPv4Subnet([0xAC, 0x10, 0x00, 0x00], [0xFF, 0xF0, 0x00, 0x00]);

/**
    192.0.0.0/24
*/
const public IPv4Subnet ipv4SpecialPurposeAddressRegistrySubnet =
new IPv4Subnet([0xC0, 0x00, 0x00, 0x00], [0xFF, 0xFF, 0xFF, 0x00]);

/**
    192.0.2.0/24
*/
const public IPv4Subnet ipv4Test192Subnet =
new IPv4Subnet([0xC0, 0x00, 0x02, 0x00], [0xFF, 0xFF, 0xFF, 0x00]);

//REVIEW: Consider renaming this one.
/**
    192.88.99.0/24
*/
const public IPv4Subnet ipv46To4AnycastRelaySubnet =
new IPv4Subnet([0xC0, 0x58, 0x63, 0x00], [0xFF, 0xFF, 0xFF, 0x00]);

/**
    192.168.0.0/16
*/
const public IPv4Subnet ipv4Local192Subnet =
new IPv4Subnet([0xC0, 0xA8, 0x00, 0x00], [0xFF, 0xFF, 0x00, 0x00]);

/**
    198.18.0.0/15
*/
const public IPv4Subnet ipv4InternetworkTestingSubnet =
new IPv4Subnet([0xC6, 0x12, 0x00, 0x00], [0xFF, 0xFE, 0x00, 0x00]);

/**
    198.51.100.0/24
*/
const public IPv4Subnet ipv4Test198Subnet =
new IPv4Subnet([0xC6, 0x33, 0x64, 0x00], [0xFF, 0xFF, 0xFF, 0x00]);

/**
    203.0.113.0/24
*/
const public IPv4Subnet ipv4Test203Subnet =
new IPv4Subnet([0xCB, 0x00, 0x71, 0x00], [0xFF, 0xFF, 0xFF, 0x00]);

/**
    224.0.0.0/4
*/
const public IPv4Subnet ipv4MulticastSubnet =
new IPv4Subnet([0xE0, 0x00, 0x00, 0x00], [0xF0, 0x00, 0x00, 0x00]);

/**
    240.0.0.0/4
*/
const public IPv4Subnet ipv4FutureUseSubnet =
new IPv4Subnet([0xE0, 0x00, 0x00, 0x00], [0xF0, 0x00, 0x00, 0x00]);

/**
    255.255.255.255/32
*/
const public IPv4Subnet ipv4BroadcastSubnet =
new IPv4Subnet([0xFF, 0xFF, 0xFF, 0xFF], [0xFF, 0xFF, 0xFF, 0xFF]);


/// Default IPv4 subnets from https://en.wikipedia.org/wiki/Reserved_IP_addresses
/**
    ::/128
*/
const public IPv6Subnet ipv6UnspecifiedSubnet =
new IPv6Subnet
(
    [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ]
);

/**
    ::1/128
*/
const public IPv6Subnet ipv6LoopbackSubnet =
new IPv6Subnet
(
    [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ],
    [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ]
);

/**
    ::FFFF:0:0/96
*/
const public IPv6Subnet ipv6IPv4MappedSubnet =
new IPv6Subnet
(
    [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    100::/64
*/
const public IPv6Subnet ipv6DiscardSubnet =
new IPv6Subnet
(
    [ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    64:FF9B::/96
*/
const public IPv6Subnet ipv6TranslationSubnet =
new IPv6Subnet
(
    [ 0x00, 0x64, 0xFF, 0x9B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    2001::/32
*/
const public IPv6Subnet ipv6TeredoSubnet =
new IPv6Subnet
(
    [ 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    2001:10::/28
    Deprecated
*/
const public IPv6Subnet ipv6OrchidSubnet =
new IPv6Subnet
(
    [ 0x20, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    2001:20::/28
*/
const public IPv6Subnet ipv6OrchidV2Subnet =
new IPv6Subnet
(
    [ 0x20, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    2001:0DB8::/32
*/
const public IPv6Subnet ipv6ExampleSubnet =
new IPv6Subnet
(
    [ 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    2002::/16
*/
const public IPv6Subnet ipv6to4Subnet =
new IPv6Subnet
(
    [ 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    FC00::/7
*/
const public IPv6Subnet ipv6UniqueLocalSubnet =
new IPv6Subnet
(
    [ 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    FE80::/10
*/
const public IPv6Subnet ipv6LinkLocalSubnet =
new IPv6Subnet
(
    [ 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
);

/**
    FF00::/8
*/
const public IPv6Subnet ipv6MulticastSubnet =
new IPv6Subnet
(
    [ 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    [ 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
);
