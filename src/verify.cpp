#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

using namespace libsnark;
using namespace std;

#define BASE64_PAD '='
#define BASE64DE_FIRST '+'
#define BASE64DE_LAST 'z'
static const char base64en[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/',
};

static const unsigned char base64de[] = {
	   255, 255, 255, 255, 255, 255, 255, 255,
	   255, 255, 255, 255, 255, 255, 255, 255,
	   255, 255, 255, 255, 255, 255, 255, 255,
	   255, 255, 255, 255, 255, 255, 255, 255,
	   255, 255, 255, 255, 255, 255, 255, 255,
	   255, 255, 255,  62, 255, 255, 255,  63,
	    52,  53,  54,  55,  56,  57,  58,  59,
	    60,  61, 255, 255, 255, 255, 255, 255,
	   255,   0,   1,  2,   3,   4,   5,    6,
	     7,   8,   9,  10,  11,  12,  13,  14,
	    15,  16,  17,  18,  19,  20,  21,  22,
	    23,  24,  25, 255, 255, 255, 255, 255,
	   255,  26,  27,  28,  29,  30,  31,  32,
	    33,  34,  35,  36,  37,  38,  39,  40,
	    41,  42,  43,  44,  45,  46,  47,  48,
	    49,  50,  51, 255, 255, 255, 255, 255
};

unsigned int
base64_decode(const char *in, unsigned int inlen, unsigned char *out)
{
	unsigned int i;
	unsigned int j;
	unsigned char c;

	if (inlen & 0x3) {
		return 0;
	}
	for (i = j = 0; i < inlen; i++) {
		if (in[i] == BASE64_PAD) {
			break;
		}
		if (in[i] < BASE64DE_FIRST || in[i] > BASE64DE_LAST) {
			return 0;
		}
		c = base64de[(unsigned char)in[i]];
		if (c == 255) {
			return 0;
		}
		switch (i & 0x3) {
		case 0:
			out[j] = (c << 2) & 0xFF;
			break;
		case 1:
			out[j++] |= (c >> 4) & 0x3;
			out[j] = (c & 0xF) << 4; 
			break;
		case 2:
			out[j++] |= (c >> 2) & 0xF;
			out[j] = (c & 0x3) << 6;
			break;
		case 3:
			out[j++] |= c;
			break;
		}
	}
	return j;
}


r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> read_proof(FILE *f)
{
    puts("enter read_proof");
    int siz;
    int in_len;
    fscanf(f, "%*s %d %d", &siz, &in_len);
    char *p = (char *)malloc(in_len);
    unsigned char *pp = (unsigned char *)malloc(siz);
    fscanf(f, "%s", p);
    base64_decode(p, strlen(p), pp);
    free(p);
    puts("leave read_proof");
    return *(r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> *)pp;
}

r1cs_gg_ppzksnark_verification_key<default_r1cs_gg_ppzksnark_pp> read_vk(FILE *f)
{
    puts("enter read_vk");
    int siz;
    int in_len;
    fscanf(f, "%*s %d %d", &siz, &in_len);
    char *p = (char *)malloc(in_len);
    fscanf(f, "%s", p);
    unsigned char *pp = (unsigned char *)malloc(siz);
    base64_decode(p, strlen(p), pp);
    string s;
    for (int i = 0; i < siz; i++)
    {
        s.insert(s.end(), pp[i]);
    }
    istringstream is(s);
    r1cs_gg_ppzksnark_verification_key<default_r1cs_gg_ppzksnark_pp> vk;
    is >> vk;
    free(pp);
    free(p);
    puts("leave read_vk");
    return vk;
}

int main(int argc, char **argv)
{
    typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

    // Initialize the curve parameters
    default_r1cs_gg_ppzksnark_pp::init_public_params();

    // Create protoboard
    protoboard<FieldT> pb;
    vector<pb_variable<FieldT>> variables;
    if (argc != 3)
    {
        printf("usage: %s arith arith_primary_input", argv[0]);
        return 2;
    }
    FILE *arith = fopen(argv[1], "r");
    FILE *in = fopen(argv[2], "r");
    if (!(arith && in))
    {
        puts("open fail");
        return 1;
    }
    int total_var_count;
    int out_start;
    int constraint_count;
    fscanf(arith, "%*s %d", &total_var_count);
    for (int i = 0; i < total_var_count; i++)
    {
        pb_variable<FieldT> *v = new pb_variable<FieldT>;
        variables.push_back(*v);
    }
    fscanf(arith, "%*s %d\n", &out_start);
    for (int i = out_start; i < total_var_count; i++)
    {
        char s[16];
        sprintf(s, "var_%d", i);
        variables[i].allocate(pb, s);
    }
    for (int i = 0; i < out_start; i++)
    {
        char s[16];
        sprintf(s, "var_%d", i);
        variables[i].allocate(pb, s);
    }
    pb.set_input_sizes(total_var_count - out_start);
    fscanf(arith, "%*s %d", &constraint_count);
    long long a, b, c;
    char op[16];
    for (int i = 0; i < constraint_count; i++)
    {
        fscanf(arith, "%s %lld %lld %lld", op, &a, &b, &c);
        if (strcmp(op, "mul") == 0 || strcmp(op, "div") == 0)
        {
            pb.add_r1cs_constraint(r1cs_constraint<FieldT>(variables[a], variables[b], variables[c]));
        }
        else if (strcmp(op, "add") == 0)
        {
            pb.add_r1cs_constraint(r1cs_constraint<FieldT>(variables[a] + variables[b], 1, variables[c]));
        }
        else if (strcmp(op, "constmul") == 0)
        {
            pb.add_r1cs_constraint(r1cs_constraint<FieldT>(variables[a], b, variables[c]));
        }
    }

    for (int i = 0; i < total_var_count - out_start; i++)
    {
        long long v;
        int index;
        fscanf(in, "%d %lld", &index, &v);
        pb.val(variables[index]) = v;
    }

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

    puts("leave read_primary_input");
    auto p = read_proof(in);
    auto vk = read_vk(in);

    bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(vk, pb.primary_input(), p);
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    // cout << "Primary (public) input: " << pb.primary_input() << endl;
    // cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;

    fclose(arith);
    fclose(in);
}
