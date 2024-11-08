package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func getCoinAmount(coinaddr []byte) *big.Int {
	conn, err := GetGRPCClient()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)
	peerId := GetPeerIDFromConfig(NodeConfig)
	privKey, err := GetPrivKeyFromConfig(NodeConfig)
	if err != nil {
		panic(err)
	}

	pub, err := privKey.GetPublic().Raw()
	if err != nil {
		panic(err)
	}

	addr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		panic(err)
	}

	addrBytes := addr.FillBytes(make([]byte, 32))
	resp, err := client.GetTokensByAccount(
		context.Background(),
		&protobufs.GetTokensByAccountRequest{
			Address: addrBytes,
		},
	)
	if err != nil {
		panic(err)
	}

	if len(resp.Coins) != len(resp.FrameNumbers) {
		panic("invalid response from RPC")
	}

	altAddr, err := poseidon.HashBytes([]byte(pub))
	if err != nil {
		panic(err)
	}

	altAddrBytes := altAddr.FillBytes(make([]byte, 32))
	resp2, err := client.GetTokensByAccount(
		context.Background(),
		&protobufs.GetTokensByAccountRequest{
			Address: altAddrBytes,
		},
	)
	if err != nil {
		panic(err)
	}

	if len(resp.Coins) != len(resp.FrameNumbers) {
		panic("invalid response from RPC")
	}

	var amount *big.Int
	for i, coin := range resp.Coins {
		if bytes.Equal(resp.Addresses[i], coinaddr) {
			amount = new(big.Int).SetBytes(coin.Amount)
		}
	}
	for i, coin := range resp2.Coins {
		if bytes.Equal(resp.Addresses[i], coinaddr) {
			amount = new(big.Int).SetBytes(coin.Amount)
		}
	}
	return amount
}

var parts int64
var splitCmd = &cobra.Command{
	Use:   "split",
	Short: "Splits a coin into multiple coins",
	Long: `Splits a coin into multiple coins:

	split <OfCoin> <Amounts>...
	split <OfCoin> -p/--parts <Parts>

	OfCoin - the address of the coin to split
	Amounts - the sets of amounts to split
	Parts - the number of parts to split the coin into
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 3 && parts == 1 {
			fmt.Println("did you forget to specify <OfCoin> and <Amounts>?")
			os.Exit(1)
		}
		if len(args) < 1 && parts > 1 {
			fmt.Println("did you forget to specify <OfCoin>?")
			os.Exit(1)
		}
		if len(args) > 1 && parts > 1 {
			fmt.Println("-p/--parts can't be combined with <Amounts>")
			os.Exit(1)
		}
		if parts > 100 {
			fmt.Println("too many parts, maximum is 100")
			os.Exit(1)
		}

		payload := []byte("split")
		coinaddrHex, _ := strings.CutPrefix(args[0], "0x")
		coinaddr, err := hex.DecodeString(coinaddrHex)
		if err != nil {
			panic(err)
		}
		coin := &protobufs.CoinRef{
			Address: coinaddr,
		}
		payload = append(payload, coinaddr...)

		// split the coin into parts
		amounts := [][]byte{}
		if parts > 1 {
			// get the amount of the coin to be split
			coinAmount := getCoinAmount(coinaddr)

			// split the coin amount into parts
			amount := new(big.Int).Div(coinAmount, big.NewInt(parts))
			for i := int64(0); i < parts; i++ {
				amountBytes := amount.FillBytes(make([]byte, 32))
				amounts = append(amounts, amountBytes)
				payload = append(payload, amountBytes...)
			}

			// if there is a remainder, we need to add it as a separate amount
			// because the amounts must sum to the original coin amount
			remainder := new(big.Int).Mod(coinAmount, big.NewInt(parts))
			if remainder.Cmp(big.NewInt(0)) != 0 {
				remainderBytes := remainder.FillBytes(make([]byte, 32))
				amounts = append(amounts, remainderBytes)
				payload = append(payload, remainderBytes...)
			}
		} else {
			// split the coin into the user provided amounts
			conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
			for _, amt := range args[1:] {
				amount, err := decimal.NewFromString(amt)
				if err != nil {
					fmt.Println("invalid amount, must be a decimal number like 0.02 or 2")
					os.Exit(1)
				}
				amount = amount.Mul(decimal.NewFromBigInt(conversionFactor, 0))
				amountBytes := amount.BigInt().FillBytes(make([]byte, 32))
				amounts = append(amounts, amountBytes)
				payload = append(payload, amountBytes...)
			}
		}

		conn, err := GetGRPCClient()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		client := protobufs.NewNodeServiceClient(conn)
		key, err := GetPrivKeyFromConfig(NodeConfig)
		if err != nil {
			panic(err)
		}

		sig, err := key.Sign(payload)
		if err != nil {
			panic(err)
		}

		pub, err := key.GetPublic().Raw()
		if err != nil {
			panic(err)
		}

		_, err = client.SendMessage(
			context.Background(),
			&protobufs.TokenRequest{
				Request: &protobufs.TokenRequest_Split{
					Split: &protobufs.SplitCoinRequest{
						OfCoin:  coin,
						Amounts: amounts,
						Signature: &protobufs.Ed448Signature{
							Signature: sig,
							PublicKey: &protobufs.Ed448PublicKey{
								KeyValue: pub,
							},
						},
					},
				},
			},
		)
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	splitCmd.Flags().Int64VarP(&parts, "parts", "p", 1, "the number of parts to split the coin into")
	tokenCmd.AddCommand(splitCmd)
}
