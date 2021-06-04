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
base64_encode(const unsigned char *in, unsigned int inlen, char *out)
{
	int s;
	unsigned int i;
	unsigned int j;
	unsigned char c;
	unsigned char l;

	s = 0;
	l = 0;
	for (i = j = 0; i < inlen; i++) {
		c = in[i];

		switch (s) {
		case 0:
			s = 1;
			out[j++] = base64en[(c >> 2) & 0x3F];
			break;
		case 1:
			s = 2;
			out[j++] = base64en[((l & 0x3) << 4) | ((c >> 4) & 0xF)];
			break;
		case 2:
			s = 0;
			out[j++] = base64en[((l & 0xF) << 2) | ((c >> 6) & 0x3)];
			out[j++] = base64en[c & 0x3F];
			break;
		}
		l = c;
	}

	switch (s) {
	case 1:
		out[j++] = base64en[(l & 0x3) << 4];
		out[j++] = BASE64_PAD;
		out[j++] = BASE64_PAD;
		break;
	case 2:
		out[j++] = base64en[(l & 0xF) << 2];
		out[j++] = BASE64_PAD;
		break;
	}

	out[j] = 0;

	return j;
}

void hexdump(FILE *f, const void *mem, int siz, char *name)
{
    char *s = (char *)calloc(siz * 8 / 6 + 100, 1);
    base64_encode((const unsigned char *)mem, siz, s);
    fprintf(f, "%s %d %d %s\n", name, siz, siz * 8 / 6 + 100, s);
    free(s);
}

int main(int argc, char **argv)
{
    typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

    // Initialize the curve parameters
    default_r1cs_gg_ppzksnark_pp::init_public_params();

    // Create protoboard
    protoboard<FieldT> pb;
    vector<pb_variable<FieldT>> variables;
    if (argc != 4)
    {
        printf("usage: %s arith arith_out proof", argv[0]);
        return 2;
    }
    FILE *arith = fopen(argv[1], "r");
    FILE *in = fopen(argv[2], "r");
    FILE *out = fopen(argv[3], "w");
    if (!(arith && in && out))
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
    fscanf(arith, "%*s %d", &out_start);
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
    for (int i = 0; i < total_var_count; i++)
    {
        long long v;
        int index;
        fscanf(in, "%d %llx", &index, &v);
        if (index >= out_start)
        {
            fprintf(out, "%d %lld\n", index, v);
        }
        pb.val(variables[index]) = v;
    }

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);
    const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
    ostringstream os;
    os << keypair.vk;
    string s = os.str();
    hexdump(out, &proof, sizeof(proof), "proof");
    hexdump(out, s.c_str(), s.size(), "keypair_vk");
    // bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
    // cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    // cout << "Primary (public) input: " << pb.primary_input() << endl;
    // // cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    // cout << "Verification status: " << verified << endl;
    fclose(arith);
    fclose(in);
    fclose(out);
}

