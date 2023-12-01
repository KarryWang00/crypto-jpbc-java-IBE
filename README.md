# Crypto-JPBC-IBE
Identity-Based Encryption from the Weil Pairing: https://link.springer.com/chapter/10.1007/3-540-44647-8_13
## Setup

1. generate public pairing, and related public parameters $(e,G_1,G_T,Z_r)$
2. choose random number $x\in Z_r$，as system primary private key $msk$
3. choose random number $g \in G_1$ as $G_1$ generator，compute public element $g^x$。therefor，the system public key is $pk = (g,g^x)$
4. choose hash function $H_1:{\{0,1\}}^* \rightarrow G_1^*, H_2:G_T \rightarrow \{0,1\}^n$
## KeyGen

1. given user identity identifier  $ID\in\{0,1\}^*$，mapping it to $G_1$ element，Immediate compute $Q_{ID} = H_1(ID)$
2. compute user private key $sk = Q_{ID}^x$
## Encrypt

1. target user identity $ID\in \{0,1\}^*$， compute corresponding hash value $Q_{ID} = H_1(ID)$
2. choose $r \in Z_r$，compute ciphertext $C_1 = g^r$
3. compute $g_{ID} = e(Q_{ID},g^x)^r$
4. compute ciphertext $C_2 = M \oplus H_2(g_{ID})$，where $M\in \{0,1\}^n$ is a plaintext
5. final ciphertext $(C_1,C_2)$
## Decrypt

1. The key of decrypt is to recover the $g_{ID}$
2. $e(sk,C_1) = e(Q_{ID}^x,g^r) = e(Q_{ID},g)^{xr} = g_{ID}$
3. recover plaintext $M = C_2 \oplus H_2(e(sk,C_1))$
