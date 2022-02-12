package state

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type TokenInfo struct {
	price    common.Hash
	decimals common.Hash
}

func PrivateKeyGen(privateKey string) ecdsa.PrivateKey {
	var e ecdsa.PrivateKey
	e.D, _ = new(big.Int).SetString(privateKey, 16)
	e.PublicKey.Curve = secp256k1.S256()
	e.PublicKey.X, e.PublicKey.Y = e.PublicKey.Curve.ScalarBaseMult(e.D.Bytes())
	return e
}

var FLASH_LOAN_CONTRACT_ADDRESSES = []common.Address{
	//fake_solomargin.sol for testing TODO: remove after done
	common.HexToAddress("0x3DD0864668C36D27B53a98137764c99F9FD5B7B2"),
	//dYdX: Solo Margin
	common.HexToAddress("0x1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e"),
	//Aave: Lending Pool Core V1
	common.HexToAddress("0x3dfd23A6c5E8BbcFc9581d2E864a68feb6a076d3"),
	//bZx ETH iToken
	common.HexToAddress("0x77f973fcaf871459aa58cd81881ce453759281bc"),
	//Uniswap V2: DAI
	common.HexToAddress("0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11"),
}
var TRANSFER_EVENT_HASH = common.HexToHash("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
var WITHDRAW_EVENT_HASH = common.HexToHash("7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65")
var DEPOSIT_EVENT_HASH = common.HexToHash("e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c")
var FRONTRUN_ADDRESS = common.HexToAddress("1d00652d5E40173ddaCdd24FD8Cdb12228992755")
var EMPTY_ADDRESS = common.HexToAddress("ffffffffffffffffffffffffffffffffffffffff")
var FRONTRUN_SECRET_KEY = PrivateKeyGen("ad0ad85b628caae0aa45653da3e9910166376e0dd94b30696b5fa8327786c735")
var ERC_TOKEN_INFORMATION_MAP = map[common.Address]TokenInfo{
	common.HexToAddress("0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84"): {common.BigToHash(big.NewInt(2000)), common.BigToHash(big.NewInt(1))},
	//"Token B" from erc.sol for testing TODO: remove after done
	common.HexToAddress("0xee35211C4D9126D520bBfeaf3cFee5FE7B86F221"): {common.BigToHash(big.NewInt(1000)), common.BigToHash(big.NewInt(1))},
	//ETH 18
	common.HexToAddress("0x0000000000000000000000000000000000000001"): {common.BigToHash(big.NewInt(40205900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//WETH 18
	common.HexToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"): {common.BigToHash(big.NewInt(40205900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//3crv 18
	common.HexToAddress("0x6c3f90f043a72fa612cbac8115ee7e52bde6e490"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//USDP 18
	common.HexToAddress("0x8e870d67f660d95d5be530380d0ec0bd388289e1"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Fei USD 18
	common.HexToAddress("0x956f47f50a910163d8bf957cf5846d573e7f87ca"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Aave interest bearing WETH (aWETH) 18
	common.HexToAddress("0x030ba81f1c18d280636f32af80b9aad02cf0854e"): {common.BigToHash(big.NewInt(41104000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Aave variable debt bearing USDC 6
	common.HexToAddress("0x619beb58998ed2278e08620f97007e1116d5d25b"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000))},
	//Aave interest bearing USDC aUSDC 6
	common.HexToAddress("0xbcca60bb61934080951369a648fb03df4f96263c"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000))},
	//Synth sUSD 18 for testing case: https://etherscan.io/tx/0x762881b07feb63c436dee38edd4ff1f7a74c33091e534af56c9f7d49b5ecac15 TODO: change its value to 0
	common.HexToAddress("0x57ab1e02fee23774580c119740129eac7081e9d3"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//STONK 18 for testing case: https://etherscan.io/tx/0xeb008786a7d230180dbd890c76d6a7735430e836d55729a3ff6e22e254121192
	common.HexToAddress("0xb60fde5d798236fbf1e2697b2a0645380921fccf"): {common.BigToHash(big.NewInt(4)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Gastoken.io 2 for testing case: https://etherscan.io/tx/0xeb008786a7d230180dbd890c76d6a7735430e836d55729a3ff6e22e254121192
	common.HexToAddress("0x0000000000b3f879cb30fe243b4dfee438691c04"): {common.BigToHash(big.NewInt(537000)), common.BigToHash(big.NewInt(100))},
	//Balancer Pool Token 18 for testing case: https://etherscan.io/tx/0x013be97768b702fe8eccef1a40544d5ecb3c1961ad5f87fee4d16fdc08c78106
	common.HexToAddress("0x0e511aa1a137aad267dfe3a6bfca0b856c1a3682"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Eminence 18 for testing case: https://etherscan.io/tx/0x3503253131644dd9f52802d071de74e456570374d586ddd640159cf6fb9b8ad8
	common.HexToAddress("0x5ade7ae8660293f2ebfcefaba91d141d72d221e8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Eminence AAVE 18 for testing case: https://etherscan.io/tx/0x3503253131644dd9f52802d071de74e456570374d586ddd640159cf6fb9b8ad8
	common.HexToAddress("0xc08f38f43adb64d16fe9f9efcc2949d9eddec198"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BNB (BNB) 18
	common.HexToAddress("0xB8c77482e45F1F44dE1745F52C74426C631bDD52"): {common.BigToHash(big.NewInt(5292306)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Tether USD (USDT) 6
	common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000))},
	//HEX (HEX) 8
	common.HexToAddress("0x2b591e99afe9f32eaa6214f7b7629768c40eeb39"): {common.BigToHash(big.NewInt(2965)), common.BigToHash(big.NewInt(100000000))},
	//USD Coin (USDC) 6
	common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000))},
	//SHIBA INU (SHIB) 18
	common.HexToAddress("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Matic Token (MATIC) 18
	common.HexToAddress("0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0"): {common.BigToHash(big.NewInt(24342)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Binance USD (BUSD) 18
	common.HexToAddress("0x4fabb145d64652a948d72533023f6e7a623c7c53"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Crypto.com Coin (CRO) 8
	common.HexToAddress("0xa0b73e1ff0b80914ab6fe0444e65848c4c34450b"): {common.BigToHash(big.NewInt(5280)), common.BigToHash(big.NewInt(100000000))},
	//Wrapped BTC (WBTC) 8
	common.HexToAddress("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"): {common.BigToHash(big.NewInt(488430000)), common.BigToHash(big.NewInt(100000000))},
	//Wrapped UST Token (UST) 18
	common.HexToAddress("0xa47c8bf37f92abed4a126bda807a7b7498661acd"): {common.BigToHash(big.NewInt(10100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ChainLink Token (LINK) 18
	common.HexToAddress("0x514910771af9ca656af840dff83e8264ecf986ca"): {common.BigToHash(big.NewInt(194100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Dai Stablecoin (DAI) 18
	common.HexToAddress("0x6b175474e89094c44da98b954eedeac495271d0f"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//OKB (OKB) 18
	common.HexToAddress("0x75231f58b43240c9718dd58b4967c5114342a86c"): {common.BigToHash(big.NewInt(321700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//TRON (TRX) 6
	common.HexToAddress("0xe1be5d3f34e89de342ee97e6e90d405884da6c67"): {common.BigToHash(big.NewInt(790)), common.BigToHash(big.NewInt(1000000))},
	//Uniswap (UNI) 18
	common.HexToAddress("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"): {common.BigToHash(big.NewInt(150500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//stETH (stETH) 18
	common.HexToAddress("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"): {common.BigToHash(big.NewInt(39974900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Wrapped liquid staked Ether 2.0 (wstETH) 18
	common.HexToAddress("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"): {common.BigToHash(big.NewInt(39974900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Compound Ether (cETH) 8
	common.HexToAddress("0x4ddc2d193948926d02f9b1fe9e1daa0718270ed5"): {common.BigToHash(big.NewInt(805900)), common.BigToHash(big.NewInt(100000000))},
	//VeChain (VEN) 18
	common.HexToAddress("0xd850942ef8811f2a866692a623011bde52a462c1"): {common.BigToHash(big.NewInt(830)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Wrapped Filecoin (WFIL) 18
	common.HexToAddress("0x6e1A19F235bE7ED8E3369eF73b196C07257494DE"): {common.BigToHash(big.NewInt(352673)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SAND (SAND) 18
	common.HexToAddress("0x3845badAde8e6dFF049820680d1F14bD3903a5d0"): {common.BigToHash(big.NewInt(51300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Magic Internet Money (MIM) 18
	common.HexToAddress("0x99d8a9c45b2eca8864373a26d1459e3dff1e17f3"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Wrapped Decentraland MANA (wMANA) 18
	common.HexToAddress("0xfd09cf7cfffa9932e33668311c4777cb9db3c9be"): {common.BigToHash(big.NewInt(32599)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Compound Dai (cDAI) 8
	common.HexToAddress("0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643"): {common.BigToHash(big.NewInt(218)), common.BigToHash(big.NewInt(100000000))},
	//Theta Token (THETA) 18
	common.HexToAddress("0x3883f5e181fccaf8410fa61e12b59bad963fb645"): {common.BigToHash(big.NewInt(41908)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Fantom Token (FTM) 18
	common.HexToAddress("0x4e15361fd6b4bb609fa63c81a2be19d873717870"): {common.BigToHash(big.NewInt(14900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Graph Token (GRT) 18
	common.HexToAddress("0xc944e90c64b2c07662a292be6244bdf05cda44a7"): {common.BigToHash(big.NewInt(7102)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Compound USD Coin (cUSDC) 8
	common.HexToAddress("0x39aa39c021dfbae8fac545936693ac917d5e7563"): {common.BigToHash(big.NewInt(225)), common.BigToHash(big.NewInt(100000000))},
	//Bitfinex LEO Token (LEO) 18
	common.HexToAddress("0x2af5d2ad76741191d15dfe7bf6ac92d4bd912ca3"): {common.BigToHash(big.NewInt(36100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Gala (GALA) 8
	common.HexToAddress("0x15D4c048F83bd7e37d49eA4C83a07267Ec4203dA"): {common.BigToHash(big.NewInt(4417)), common.BigToHash(big.NewInt(100000000))},
	//LoopringCoin V2 (LRC) 18
	common.HexToAddress("0xbbbbca6a901c926f240b89eacb641d8aec7aeafd"): {common.BigToHash(big.NewInt(23600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//HarmonyOne (ONE) 18
	common.HexToAddress("0x799a4202c12ca952cb311598a024c80ed371a41e"): {common.BigToHash(big.NewInt(2450)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BitTorrent (BTT) 6
	common.HexToAddress("0xe83cccfabd4ed148903bf36d4283ee7c8b3494d1"): {common.BigToHash(big.NewInt(27)), common.BigToHash(big.NewInt(1000000))},
	//Quant (QNT) 18
	common.HexToAddress("0x4a220e6096b25eadb88358cb44068a3248254675"): {common.BigToHash(big.NewInt(1836699)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Amp (AMP) 18
	common.HexToAddress("0xff20817765cb7f73d4bde2e66e067e58d11095c2"): {common.BigToHash(big.NewInt(484)), common.BigToHash(big.NewInt(1000000000000000000))},
	//EnjinCoin (ENJ) 18
	common.HexToAddress("0xf629cbd94d3791c9250152bd8dfbdf380e2a3b9c"): {common.BigToHash(big.NewInt(24600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Maker (MKR) 18
	common.HexToAddress("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"): {common.BigToHash(big.NewInt(24336000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Huobi BTC (HBTC) 18
	common.HexToAddress("0x0316EB71485b0Ab14103307bf65a021042c6d380"): {common.BigToHash(big.NewInt(491120000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Aave interest bearing CRV (aCRV) 18
	common.HexToAddress("0x8dae6cb04688c62d939ed9b68d32bc62e49970b1"): {common.BigToHash(big.NewInt(48000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Spell Token (SPELL) 18
	common.HexToAddress("0x090185f2135308bad17527004364ebcc2d37e5f6"): {common.BigToHash(big.NewInt(222)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BAT (BAT) 18
	common.HexToAddress("0x0d8775f648430679a709e98d2b0cb6250d2887ef"): {common.BigToHash(big.NewInt(11600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//KuCoin Token (KCS) 6
	common.HexToAddress("0xf34960d9d60be18cc1d5afc1a6f012a723a28811"): {common.BigToHash(big.NewInt(216916)), common.BigToHash(big.NewInt(1000000))},
	//Celsius (CEL) 4
	common.HexToAddress("0xaaaebe6fe48e54f431b0c390cfaf0b017d09d42d"): {common.BigToHash(big.NewInt(38500)), common.BigToHash(big.NewInt(10000))},
	//HuobiToken (HT) 18
	common.HexToAddress("0x6f259637dcd74c767781e37bc6133cd6a68aa161"): {common.BigToHash(big.NewInt(100200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Wrapped Celo (wCELO) 18
	common.HexToAddress("0xe452e6ea2ddeb012e20db73bf5d3863a3ac8d77a"): {common.BigToHash(big.NewInt(42676)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Frax (FRAX) 18
	common.HexToAddress("0x853d955acef822db058eb8505911ed77f175b99e"): {common.BigToHash(big.NewInt(10100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chiliZ (CHZ) 18
	common.HexToAddress("0x3506424f91fd33084466f402d5d97f05f8e3b4af"): {common.BigToHash(big.NewInt(2828)), common.BigToHash(big.NewInt(1000000000000000000))},
	//HoloToken (HOT) 18
	common.HexToAddress("0x6c6ee5e31d828de241282b9606c8e98ea48526e2"): {common.BigToHash(big.NewInt(83)), common.BigToHash(big.NewInt(1000000000000000000))},
	//TrueUSD (TUSD) 18
	common.HexToAddress("0x0000000000085d4780B73119b644AE5ecd22b376"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Nexo (NEXO) 18
	common.HexToAddress("0xb62132e35a6c13ee1ee0f84dc5d40bad8d815206"): {common.BigToHash(big.NewInt(22200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yearn.finance (YFI) 18
	common.HexToAddress("0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e"): {common.BigToHash(big.NewInt(345110000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//IoTeX Network (IOTX) 18
	common.HexToAddress("0x6fb3e0a217407efff7ca062d46c26e5d60a14d69"): {common.BigToHash(big.NewInt(1287)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Compound (COMP) 18
	common.HexToAddress("0xc00e94cb662c3520282e6f5717214004a7f26888"): {common.BigToHash(big.NewInt(1946800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SushiToken (SUSHI) 18
	common.HexToAddress("0x6b3595068778dd592e39a122f4f5a5cf09c90fe2"): {common.BigToHash(big.NewInt(58500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//XinFin XDCE (XDCE) 18
	common.HexToAddress("0x41ab1b6fcbb2fa9dced81acbdec13ea6315f2bf2"): {common.BigToHash(big.NewInt(858)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Synthetix Network Token (SNX) 18
	common.HexToAddress("0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f"): {common.BigToHash(big.NewInt(53700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//1INCH Token (1INCH) 18
	common.HexToAddress("0x111111111117dc0aa78b770fa6a738034120c302"): {common.BigToHash(big.NewInt(24600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Pax Dollar (USDP) 18
	common.HexToAddress("0x8e870d67f660d95d5be530380d0ec0bd388289e1"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//NXM (NXM) 18
	common.HexToAddress("0xd7c49cee7e9188cca6ad8ff264c1da2e69d4cf3b"): {common.BigToHash(big.NewInt(1336500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Livepeer Token (LPT) 18
	common.HexToAddress("0x58b6a8a3302369daec383334672404ee733ab239"): {common.BigToHash(big.NewInt(373900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//WQtum (WQTUM) 18
	common.HexToAddress("0x3103df8f05c4d8af16fd22ae63e406b97fec6938"): {common.BigToHash(big.NewInt(92241)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Compound USDT (cUSDT) 8
	common.HexToAddress("0xf650c3d88d12db855b8bf7d11be6c55a4e07dcc9"): {common.BigToHash(big.NewInt(217)), common.BigToHash(big.NewInt(100000000))},
	//WAX Token (WAX) 8
	common.HexToAddress("0x39bb259f66e1c59d5abef88375979b4d20d98022"): {common.BigToHash(big.NewInt(4611)), common.BigToHash(big.NewInt(100000000))},
	//OMG Network (OMG) 18
	common.HexToAddress("0xd26114cd6EE289AccF82350c8d8487fedB8A0C07"): {common.BigToHash(big.NewInt(61000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Gnosis (GNO) 18
	common.HexToAddress("0x6810e776880c02933d47db1b9fc05908e5386b96"): {common.BigToHash(big.NewInt(4537300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//renBTC (renBTC) 8
	common.HexToAddress("0xeb4c2781e4eba804ce9a9803c67d0893436bb27d"): {common.BigToHash(big.NewInt(498430000)), common.BigToHash(big.NewInt(100000000))},
	//Ethereum Name Service (ENS) 18
	common.HexToAddress("0xc18360217d8f7ab5e7c516566761ea12ce7f9d72"): {common.BigToHash(big.NewInt(409365)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pTokens SAFEMOON (pSAFEMOON) 18
	common.HexToAddress("0x16631e53c20fd2670027c6d53efe2642929b285c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Zilliqa (ZIL) 12
	common.HexToAddress("0x05f4a42e251f2d52b8ed15e9fedaacfcef1fad27"): {common.BigToHash(big.NewInt(641)), common.BigToHash(big.NewInt(1000000000000))},
	//Telcoin (TEL) 2
	common.HexToAddress("0x467Bccd9d29f223BcE8043b84E8C8B282827790F"): {common.BigToHash(big.NewInt(129)), common.BigToHash(big.NewInt(100))},
	//Bancor (BNT) 18
	common.HexToAddress("0x1f573d6fb3f13d689ff844b4ce37794d79a7ff1c"): {common.BigToHash(big.NewInt(33300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Rocket Pool (RPL) 18
	common.HexToAddress("0xd33526068d116ce69f19a9ee46f0bd304f21a51f"): {common.BigToHash(big.NewInt(458100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Rocket Pool (RPL) 18
	common.HexToAddress("0xb4efd85c19999d84251304bda99e90b92300bd93"): {common.BigToHash(big.NewInt(458100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Illuvium (ILV) 18
	common.HexToAddress("0x767fe9edc9e0df98e07454847909b5e959d7ca0e"): {common.BigToHash(big.NewInt(11055900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Wootrade Network (WOO) 18
	common.HexToAddress("0x4691937a7508860f876c9c0a2a617e7d9e945d4b"): {common.BigToHash(big.NewInt(7920)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ZRX (ZRX) 18
	common.HexToAddress("0xe41d2489571d322189246dafa5ebde1f4699f498"): {common.BigToHash(big.NewInt(7877)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Dogelon (ELON) 18
	common.HexToAddress("0x761d38e5ddf6ccf6cf7c55759d5210750b5d60f3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Frax Share (FXS) 18
	common.HexToAddress("0x3432b6a60d23ca0dfca7761b7ab56459d9c964d0"): {common.BigToHash(big.NewInt(175500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//UMA Voting Token v1 (UMA) 18
	common.HexToAddress("0x04Fa0d235C4abf4BcF4787aF4CF447DE572eF828"): {common.BigToHash(big.NewInt(89900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SwissBorg (CHSB) 8
	common.HexToAddress("0xba9d4199fab4f26efe3551d490e3821486f135ba"): {common.BigToHash(big.NewInt(5961)), common.BigToHash(big.NewInt(100000000))},
	//IOSToken (IOST) 18
	common.HexToAddress("0xfa1a856cfa3409cfa145fa4e20eb270df3eb21ab"): {common.BigToHash(big.NewInt(302)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Boba Token (BOBA) 18
	common.HexToAddress("0x42bbfa2e77757c645eeaad1655e0911a7553efbc"): {common.BigToHash(big.NewInt(35100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Fei USD (FEI) 18
	common.HexToAddress("0x956F47F50A910163D8BF957Cf5846D573E7f87CA"): {common.BigToHash(big.NewInt(9978)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dYdX (DYDX) 18
	common.HexToAddress("0x92d6c1e31e14520e676a687f0a93788b716beff5"): {common.BigToHash(big.NewInt(75700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//XY Oracle (XYO) 18
	common.HexToAddress("0x55296f69f40ea6d20e478533c15a6b08b654e758"): {common.BigToHash(big.NewInt(385)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Serum (SRM) 6
	common.HexToAddress("0x476c5E26a75bd202a9683ffD34359C0CC15be0fF"): {common.BigToHash(big.NewInt(35500)), common.BigToHash(big.NewInt(1000000))},
	//Golem Network Token (GLM) 18
	common.HexToAddress("0x7DD9c5Cba05E151C895FDe1CF355C9A1D5DA6429"): {common.BigToHash(big.NewInt(4539)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Polymath (POLY) 18
	common.HexToAddress("0x9992ec3cf6a55b00978cddf2b27bc6882d88d1ec"): {common.BigToHash(big.NewInt(5050)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Mask Network (MASK) 18
	common.HexToAddress("0x69af81e73a73b40adf4f3d4223cd9b1ece623074"): {common.BigToHash(big.NewInt(108400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Tribe (TRIBE) 18
	common.HexToAddress("0xc7283b66eb1eb5fb86327f08e1b5816b0720212b"): {common.BigToHash(big.NewInt(9210)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CelerToken (CELR) 18
	common.HexToAddress("0x4f9254c83eb525f9fcf346490bbb3ed28a81c667"): {common.BigToHash(big.NewInt(731)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Anyswap (ANY) 18
	common.HexToAddress("0xf99d58e463a2e07e5692127302c20a191861b4d6"): {common.BigToHash(big.NewInt(220703)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Trace (TRAC) 18
	common.HexToAddress("0xaa7a9ca87d3694b5755f213b5d04094b8d0f0a6f"): {common.BigToHash(big.NewInt(10900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Function X (FX) 18
	common.HexToAddress("0x8c15ef5b4b21951d50e53e4fbda8298ffad25057"): {common.BigToHash(big.NewInt(9404)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Fetch (FET) 18
	common.HexToAddress("0xaea46A60368A7bD060eec7DF8CBa43b7EF41Ad85"): {common.BigToHash(big.NewInt(5551)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Chroma (CHR) 6
	common.HexToAddress("0x8A2279d4A90B6fe1C4B30fa660cC9f926797bAA2"): {common.BigToHash(big.NewInt(6522)), common.BigToHash(big.NewInt(1000000))},
	//Synapse (SYN) 18
	common.HexToAddress("0x0f2d719407fdbeff09d87557abb7232601fd9f29"): {common.BigToHash(big.NewInt(21400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//KEEP Token (KEEP) 18
	common.HexToAddress("0x85eee30c52b0b379b046fb0f85f4f3dc3009afec"): {common.BigToHash(big.NewInt(6423)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Injective Token (INJ) 18
	common.HexToAddress("0xe28b3B32B6c345A34Ff64674606124Dd5Aceca30"): {common.BigToHash(big.NewInt(80300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Ocean Token (OCEAN) 18
	common.HexToAddress("0x967da4048cD07aB37855c090aAF366e4ce1b9F48"): {common.BigToHash(big.NewInt(7835)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Paxos Gold (PAXG) 18
	common.HexToAddress("0x45804880De22913dAFE09f4980848ECE6EcbAf78"): {common.BigToHash(big.NewInt(17943700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DENT (DENT) 8
	common.HexToAddress("0x3597bfd533a99c9aa083587b074434e61eb0a258"): {common.BigToHash(big.NewInt(35)), common.BigToHash(big.NewInt(100000000))},
	//Gemini dollar (GUSD) 2
	common.HexToAddress("0x056fd409e1d7a124bd7017459dfea2f387b6d5cd"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(100))},
	//AlphaToken (ALPHA) 18
	common.HexToAddress("0xa1faa113cbe53436df28ff0aee54275c13b40975"): {common.BigToHash(big.NewInt(7125)), common.BigToHash(big.NewInt(1000000000000000000))},
	//HUSD (HUSD) 8
	common.HexToAddress("0xdf574c24545e5ffecb9a659c229253d4111d87e1"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(100000000))},
	//Energy Web Token Bridged (EWTB) 18
	common.HexToAddress("0x178c820f862b14f316509ec36b13123da19a6054"): {common.BigToHash(big.NewInt(102780)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CoinEx Token (CET) 18
	common.HexToAddress("0x081f67afa0ccf8c7b17540767bbe95df2ba8d97f"): {common.BigToHash(big.NewInt(799)), common.BigToHash(big.NewInt(1000000000000000000))},
	//MEDX TOKEN (MEDX) 8
	common.HexToAddress("0xfd1e80508f243e64ce234ea88a5fd2827c71d4b7"): {common.BigToHash(big.NewInt(3691)), common.BigToHash(big.NewInt(100000000))},
	//Tether Gold (XAUt) 6
	common.HexToAddress("0x68749665ff8d2d112fa859aa293f07a622782f38"): {common.BigToHash(big.NewInt(17930500)), common.BigToHash(big.NewInt(1000000))},
	//Swipe (SXP) 18
	common.HexToAddress("0x8ce9137d39326ad0cd6491fb5cc0cba0e089b6a9"): {common.BigToHash(big.NewInt(15400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Aragon Network Token (ANT) 18
	common.HexToAddress("0xa117000000f279d81a1d3cc75430faa017fa5a2e"): {common.BigToHash(big.NewInt(75600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Pundi X Token (PUNDIX) 18
	common.HexToAddress("0x0fd10b9899882a6f2fcb5c371e17e70fdee00c38"): {common.BigToHash(big.NewInt(11000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Rari Governance Token (RGT) 18
	common.HexToAddress("0xD291E7a03283640FDc51b121aC401383A46cC623"): {common.BigToHash(big.NewInt(233384)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Request (REQ) 18
	common.HexToAddress("0x8f8221afbb33998d8584a2b05749ba73c37a938a"): {common.BigToHash(big.NewInt(3663)), common.BigToHash(big.NewInt(1000000000000000000))},
	//StatusNetwork (SNT) 18
	common.HexToAddress("0x744d70fdbe2ba4cf95131626614a1763df805b9e"): {common.BigToHash(big.NewInt(724)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Keep3rV1 (KP3R) 18
	common.HexToAddress("0x1ceb5cb57c4d4e2b2433641b95dd330a33185a44"): {common.BigToHash(big.NewInt(9186700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//MCO (MCO) 8
	common.HexToAddress("0xb63b606ac810a52cca15e44bb630fd42d8d1d83d"): {common.BigToHash(big.NewInt(167997)), common.BigToHash(big.NewInt(100000000))},
	//Storj (STORJ) 8
	common.HexToAddress("0xb64ef51c888972c908cfacf59b47c1afbc0ab8ac"): {common.BigToHash(big.NewInt(18300)), common.BigToHash(big.NewInt(100000000))},
	//Orbs (ORBS) 18
	common.HexToAddress("0xff56cc6b1e6ded347aa0b7676c85ab0b3d08b0fa"): {common.BigToHash(big.NewInt(878)), common.BigToHash(big.NewInt(1000000000000000000))},
	//OriginToken (OGN) 18
	common.HexToAddress("0x8207c1ffc5b6804f6024322ccf34f29c3541ae26"): {common.BigToHash(big.NewInt(6228)), common.BigToHash(big.NewInt(1000000000000000000))},
	//NKN (NKN) 18
	common.HexToAddress("0x5cf04716ba20127f1e2297addcf4b5035000c9eb"): {common.BigToHash(big.NewInt(3515)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Dusk Network (DUSK) 18
	common.HexToAddress("0x940a2db1b7008b6c776d4faaca729d6d4a4aa551"): {common.BigToHash(big.NewInt(6222)), common.BigToHash(big.NewInt(1000000000000000000))},
	//UniBright (UBT) 8
	common.HexToAddress("0x8400d94a5cb0fa0d041a3788e395285d61c9ee5e"): {common.BigToHash(big.NewInt(15600)), common.BigToHash(big.NewInt(100000000))},
	//DODO bird (DODO) 18
	common.HexToAddress("0x43Dfc4159D86F3A37A5A4B3D4580b888ad7d4DDd"): {common.BigToHash(big.NewInt(8635)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Divi Exchange Token (DIVX) 18
	common.HexToAddress("0x13f11c9905a08ca76e3e853be63d4f0944326c72"): {common.BigToHash(big.NewInt(852)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BioPassport Coin (BIOT) 9
	common.HexToAddress("0xc07A150ECAdF2cc352f5586396e344A6b17625EB"): {common.BigToHash(big.NewInt(1272)), common.BigToHash(big.NewInt(1000000000))},
	//Bifrost (BFC) 18
	common.HexToAddress("0x0c7D5ae016f806603CB1782bEa29AC69471CAb9c"): {common.BigToHash(big.NewInt(2037)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BandToken (BAND) 18
	common.HexToAddress("0xba11d00c5f74255f56a5e366f4f77f5a186d7f55"): {common.BigToHash(big.NewInt(53200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ALICE (ALICE) 6
	common.HexToAddress("0xac51066d7bec65dc4589368da368b212745d63e8"): {common.BigToHash(big.NewInt(125700)), common.BigToHash(big.NewInt(1000000))},
	//Token Prometeus Network (PROM) 18
	common.HexToAddress("0xfc82bb4ba86045af6f327323a46e80412b91b27d"): {common.BigToHash(big.NewInt(131300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Orchid (OXT) 18
	common.HexToAddress("0x4575f41308EC1483f3d399aa9a2826d74Da13Deb"): {common.BigToHash(big.NewInt(3653)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BitMax token (BTMX) 18
	common.HexToAddress("0xcca0c9c383076649604eE31b20248BC04FdF61cA"): {common.BigToHash(big.NewInt(3207)), common.BigToHash(big.NewInt(1000000000000000000))},
	//RLC (RLC) 9
	common.HexToAddress("0x607F4C5BB672230e8672085532f7e901544a7375"): {common.BigToHash(big.NewInt(29800)), common.BigToHash(big.NewInt(1000000000))},
	//StormX (STMX) 18
	common.HexToAddress("0xbe9375c6a420d2eeb258962efb95551a5b722803"): {common.BigToHash(big.NewInt(222)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Balancer (BAL) 18
	common.HexToAddress("0xba100000625a3754423978a60c9317c58a424e3d"): {common.BigToHash(big.NewInt(187000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//XSGD (XSGD) 6
	common.HexToAddress("0x70e8de73ce538da2beed35d14187f6959a8eca96"): {common.BigToHash(big.NewInt(7352)), common.BigToHash(big.NewInt(1000000))},
	//Numeraire (NMR) 18
	common.HexToAddress("0x1776e1f26f98b1a5df9cd347953a26dd3cb46671"): {common.BigToHash(big.NewInt(330100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PowerLedger (POWR) 6
	common.HexToAddress("0x595832f8fc6bf59c85c527fec3740a1b7a361269"): {common.BigToHash(big.NewInt(4522)), common.BigToHash(big.NewInt(1000000))},
	//Lido DAO Token (LDO) 18
	common.HexToAddress("0x5a98fcbea516cf06857215779fd812ca3bef1b32"): {common.BigToHash(big.NewInt(29600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Ankr Eth2 Reward Bearing Certificate (aETHc) 18
	common.HexToAddress("0xE95A203B1a91a908F9B9CE46459d101078c2c3cb"): {common.BigToHash(big.NewInt(35680900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SingularityNET Token (AGIX) 8
	common.HexToAddress("0x5b7533812759b45c2b44c19e320ba2cd2681b542"): {common.BigToHash(big.NewInt(1933)), common.BigToHash(big.NewInt(100000000))},
	//Veritaseum (VERI) 18
	common.HexToAddress("0x8f3470A7388c05eE4e7AF3d01D8C722b0FF52374"): {common.BigToHash(big.NewInt(834200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//TrueFi (TRU) 8
	common.HexToAddress("0x4c19596f5aaff459fa38b0f7ed92f11ae6543784"): {common.BigToHash(big.NewInt(3230)), common.BigToHash(big.NewInt(100000000))},
	//ELF (ELF) 18
	common.HexToAddress("0xbf2179859fc6d5bee9bf9158632dc51678a4100e"): {common.BigToHash(big.NewInt(3778)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Vader (VADER) 18
	common.HexToAddress("0x2602278ee1882889b946eb11dc0e810075650983"): {common.BigToHash(big.NewInt(470)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Beta Token (BETA) 18
	common.HexToAddress("0xbe1a001fe942f96eea22ba08783140b9dcc09d28"): {common.BigToHash(big.NewInt(6425)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Dawn (DAWN) 18
	common.HexToAddress("0x580c8520deda0a441522aeae0f9f7a5f29629afa"): {common.BigToHash(big.NewInt(23000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Aurora DAO (AURA) 18
	common.HexToAddress("0xcdcfc0f66c522fd086a1b725ea3c0eeb9f9e8814"): {common.BigToHash(big.NewInt(2604)), common.BigToHash(big.NewInt(1000000000000000000))},
	//IceToken (ICE) 18
	common.HexToAddress("0xf16e81dce15b08f326220742020379b855b87df9"): {common.BigToHash(big.NewInt(153100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Proton (XPR) 4
	common.HexToAddress("0xD7EFB00d12C2c13131FD319336Fdf952525dA2af"): {common.BigToHash(big.NewInt(182)), common.BigToHash(big.NewInt(10000))},
	//Uquid Coin (UQC) 18
	common.HexToAddress("0x8806926Ab68EB5a7b909DcAf6FdBe5d93271D6e2"): {common.BigToHash(big.NewInt(147200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Crypto20 (C20) 18
	common.HexToAddress("0x26e75307fc0c021472feb8f727839531f112f317"): {common.BigToHash(big.NewInt(44100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//STPT (STPT) 18
	common.HexToAddress("0xde7d85157d9714eadf595045cc12ca4a5f3e2adb"): {common.BigToHash(big.NewInt(1104)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Iron Bank EUR (ibEUR) 18
	common.HexToAddress("0x96e61422b6a9ba0e068b6c5add4ffabc6a4aae27"): {common.BigToHash(big.NewInt(11900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Metal (MTL) 8
	common.HexToAddress("0xF433089366899D83a9f26A773D59ec7eCF30355e"): {common.BigToHash(big.NewInt(21800)), common.BigToHash(big.NewInt(100000000))},
	//Kin (KIN) 18
	common.HexToAddress("0x818fc6c2ec5986bc6e2cbf00939d90556ab12ce5"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Gitcoin (GTC) 18
	common.HexToAddress("0xde30da39c46104798bb5aa3fe8b9e0e1f348163f"): {common.BigToHash(big.NewInt(95900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//QuarkChain Token (QKC) 18
	common.HexToAddress("0xea26c4ac16d4a5a106820bc8aee85fd0b7b2b664"): {common.BigToHash(big.NewInt(204)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Compound Basic Attention Token (cBAT) 8
	common.HexToAddress("0x6c8c6b02e7b2be14d4fa6022dfd6d75921d90e4e"): {common.BigToHash(big.NewInt(238)), common.BigToHash(big.NewInt(100000000))},
	//Kyber Network Crystal v2 (KNC) 18
	common.HexToAddress("0xdeFA4e8a7bcBA345F687a2f1456F5Edd9CE97202"): {common.BigToHash(big.NewInt(12800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//FEGtoken (FEG) 9
	common.HexToAddress("0x389999216860ab8e0175387a0c90e5c52522c945"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//LCX (LCX) 18
	common.HexToAddress("0x037a54aab062628c9bbae1fdb1583c195585fe41"): {common.BigToHash(big.NewInt(2150)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Melon Token (MLN) 18
	common.HexToAddress("0xec67005c4e498ec7f55e092bd1d35cbc47c91892"): {common.BigToHash(big.NewInt(825500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//KyberNetwork (KNC) 18
	common.HexToAddress("0xdd974d5c2e2928dea5f71b9825b8b646686bd200"): {common.BigToHash(big.NewInt(12900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Synth sUSD (sUSD) 18
	common.HexToAddress("0x57ab1ec28d129707052df4df418d58a2d46d5f51"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Reputation (REPv2) 18
	common.HexToAddress("0x221657776846890989a759ba2973e427dff5c9bb"): {common.BigToHash(big.NewInt(170300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//POA ERC20 on Foundation (POA20) 18
	common.HexToAddress("0x6758b7d441a9739b98552b373703d8d3d14f9e62"): {common.BigToHash(big.NewInt(3955)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Wrapped NXM (wNXM) 18
	common.HexToAddress("0x0d438f3b5175bebc262bf23753c1e53d03432bde"): {common.BigToHash(big.NewInt(684727)), common.BigToHash(big.NewInt(1000000000000000000))},
	//MXCToken (MXC) 18
	common.HexToAddress("0x5ca381bbfb58f0092df149bd3d243b08b9a8386e"): {common.BigToHash(big.NewInt(472)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Adventure Gold (AGLD) 18
	common.HexToAddress("0x32353A6C91143bfd6C7d363B546e62a9A2489A20"): {common.BigToHash(big.NewInt(16145)), common.BigToHash(big.NewInt(1000000000000000000))},
	//STASIS EURS Token (EURS) 2
	common.HexToAddress("0xdb25f211ab05b1c97d595516f45794528a807ad8"): {common.BigToHash(big.NewInt(11399)), common.BigToHash(big.NewInt(100))},
	//Presearch (PRE) 18
	common.HexToAddress("0xEC213F83defB583af3A000B1c0ada660b1902A0F"): {common.BigToHash(big.NewInt(2813)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Decentral Games (DG) 18
	common.HexToAddress("0x4b520c812e8430659fc9f12f6d0c39026c83588d"): {common.BigToHash(big.NewInt(3677)), common.BigToHash(big.NewInt(1000000000000000000))},
	//FunFair (FUN) 8
	common.HexToAddress("0x419d0d8bdd9af5e606ae2232ed285aff190e711b"): {common.BigToHash(big.NewInt(102)), common.BigToHash(big.NewInt(100000000))},
	//Automata (ATA) 18
	common.HexToAddress("0xa2120b9e674d3fc3875f415a7df52e382f141225"): {common.BigToHash(big.NewInt(6244)), common.BigToHash(big.NewInt(1000000000000000000))},
	//AIOZ Network (AIOZ) 18
	common.HexToAddress("0x626e8036deb333b408be468f951bdb42433cbf18"): {common.BigToHash(big.NewInt(5053)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CocosToken (COCOS) 18
	common.HexToAddress("0x0c6f5f7d555e7518f6841a79436bd2b1eef03381"): {common.BigToHash(big.NewInt(24400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SpookyToken (BOO) 18
	common.HexToAddress("0x55af5865807b196bd0197e0902746f31fbccfa58"): {common.BigToHash(big.NewInt(150500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//EthLend (LEND) 18
	common.HexToAddress("0x80fB784B7eD66730e8b1DBd9820aFD29931aab03"): {common.BigToHash(big.NewInt(19500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Smooth Love Potion (SLP) 0
	common.HexToAddress("0xcc8fa225d80b9c7d42f96e9570156c65d6caaa25"): {common.BigToHash(big.NewInt(310)), common.BigToHash(big.NewInt(1))},
	//Compound 0x (cZRX) 8
	common.HexToAddress("0xb3319f5d18bc0d84dd1b4825dcde5d5f7266d407"): {common.BigToHash(big.NewInt(161)), common.BigToHash(big.NewInt(100000000))},
	//Wrapped Celo USD (wCUSD) 18
	common.HexToAddress("0xad3e3fc59dff318beceaab7d00eb4f68b1ecf195"): {common.BigToHash(big.NewInt(9952)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DeversiFi Token (DVF) 18
	common.HexToAddress("0xdddddd4301a082e62e84e43f474f044423921918"): {common.BigToHash(big.NewInt(79500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Decentral Games Governance (xDG) 18
	common.HexToAddress("0x4f81c790581b240a5c948afd173620ecc8c71c8d"): {common.BigToHash(big.NewInt(3778)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CarryToken (CRE) 18
	common.HexToAddress("0x115ec79f1de567ec68b7ae7eda501b406626478e"): {common.BigToHash(big.NewInt(106)), common.BigToHash(big.NewInt(1000000000000000000))},
	//QANX Token (QANX) 18
	common.HexToAddress("0xaaa7a10a8ee237ea61e8ac46c50a8db8bcc1baaa"): {common.BigToHash(big.NewInt(959)), common.BigToHash(big.NewInt(1000000000000000000))},
	//TORN Token (TORN) 18
	common.HexToAddress("0x77777feddddffc19ff86db637967013e6c6a116c"): {common.BigToHash(big.NewInt(397700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mStable USD (mUSD) 18
	common.HexToAddress("0xe2f2a5c287993345a840db3b0845fbc70f5935a5"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Litentry (LIT) 18
	common.HexToAddress("0xb59490ab09a0f526cc7305822ac65f2ab12f9723"): {common.BigToHash(big.NewInt(29800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Nuls (NULS) 8
	common.HexToAddress("0xa2791bdf2d5055cda4d46ec17f9f429568275047"): {common.BigToHash(big.NewInt(9082)), common.BigToHash(big.NewInt(100000000))},
	//Eden (EDEN) 18
	common.HexToAddress("0x1559fa1b8f28238fd5d76d9f434ad86fd20d1559"): {common.BigToHash(big.NewInt(9465)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Quickswap (QUICK) 18
	common.HexToAddress("0x6c28AeF8977c9B773996d0e8376d2EE379446F2f"): {common.BigToHash(big.NewInt(2371100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Mainframe Token (MFT) 18
	common.HexToAddress("0xdf2c7238198ad8b389666574f2d8bc411a4b7428"): {common.BigToHash(big.NewInt(88)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Ribbon (RBN) 18
	common.HexToAddress("0x6123b0049f904d730db3c36a31167d9d4121fa6b"): {common.BigToHash(big.NewInt(16700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Shiden (SDN) 18
	common.HexToAddress("0x00e856ee945a49bb73436e719d96910cd9d116a4"): {common.BigToHash(big.NewInt(14900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Ampleforth Governance (FORTH) 18
	common.HexToAddress("0x77fba179c79de5b7653f68b5039af940ada60ce0"): {common.BigToHash(big.NewInt(93000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BarnBridge Governance Token (BOND) 18
	common.HexToAddress("0x0391D2021f89DC339F60Fff84546EA23E337750f"): {common.BigToHash(big.NewInt(154500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bZx Protocol Token (BZRX) 18
	common.HexToAddress("0x56d811088235F11C8920698a204A5010a788f4b3"): {common.BigToHash(big.NewInt(2153)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Cortex Coin (CTXC) 18
	common.HexToAddress("0xea11755ae41d889ceec39a63e6ff75a02bc1c00d"): {common.BigToHash(big.NewInt(4186)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ParaSwap (PSP) 18
	common.HexToAddress("0xcafe001067cdef266afb7eb5a286dcfd277f3de5"): {common.BigToHash(big.NewInt(3781)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Tellor Tributes (TRB) 18
	common.HexToAddress("0x88df592f8eb5d7bd38bfef7deb0fbc02cf3778a0"): {common.BigToHash(big.NewInt(328400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Bluzelle (BLZ) 18
	common.HexToAddress("0x5732046a883704404f284ce41ffadd5b007fd668"): {common.BigToHash(big.NewInt(2357)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hoge.finance (HOGE) 9
	common.HexToAddress("0xfad45e47083e4607302aa43c65fb3106f1cd7607"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000))},
	//Propy (PRO) 8
	common.HexToAddress("0x226bb599a12c826476e3a771454697ea52e9e220"): {common.BigToHash(big.NewInt(13100)), common.BigToHash(big.NewInt(100000000))},
	//DIAToken (DIA) 18
	common.HexToAddress("0x84cA8bc7997272c7CfB4D0Cd3D55cd942B3c9419"): {common.BigToHash(big.NewInt(12600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//FOX (FOX) 18
	common.HexToAddress("0xc770eefad204b5180df6a14ee197d99d808ee52d"): {common.BigToHash(big.NewInt(6189)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PlatonCoin (PLTC) 18
	common.HexToAddress("0x429D83Bb0DCB8cdd5311e34680ADC8B12070a07f"): {common.BigToHash(big.NewInt(7890)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Aergo (AERGO) 18
	common.HexToAddress("0x91Af0fBB28ABA7E31403Cb457106Ce79397FD4E6"): {common.BigToHash(big.NewInt(2763)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Sai Stablecoin v1.0 (SAI) 18
	common.HexToAddress("0x89d24a6b4ccb1b6faa2625fe562bdd9a23260359"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//OVR (OVR) 18
	common.HexToAddress("0x21bfbda47a0b4b5b1248c767ee49f7caa9b23697"): {common.BigToHash(big.NewInt(24800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//GRID (GRID) 12
	common.HexToAddress("0x12b19d3e2ccc14da04fae33e63652ce469b3f2fd"): {common.BigToHash(big.NewInt(18300)), common.BigToHash(big.NewInt(1000000000000))},
	//Rarible (RARI) 18
	common.HexToAddress("0xfca59cd816ab1ead66534d82bc21e7515ce441cf"): {common.BigToHash(big.NewInt(130900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PAID Network (PAID) 18
	common.HexToAddress("0x1614f18fc94f47967a3fbe5ffcd46d4e7da3d787"): {common.BigToHash(big.NewInt(5886)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Bread (BRD) 18
	common.HexToAddress("0x558ec3152e2eb2174905cd19aea4e34a23de9ad6"): {common.BigToHash(big.NewInt(8114)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Covalent Query Token (CQT) 18
	common.HexToAddress("0xd417144312dbf50465b1c641d016962017ef6240"): {common.BigToHash(big.NewInt(5470)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BetProtocolToken (BEPRO) 18
	common.HexToAddress("0xcf3c8be2e2c42331da80ef210e9b1b307c03d36a"): {common.BigToHash(big.NewInt(100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Moss Coin (MOC) 18
	common.HexToAddress("0x865ec58b06bf6305b886793aa20a2da31d034e68"): {common.BigToHash(big.NewInt(2436)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Bytom (BTM) 8
	common.HexToAddress("0xcb97e65f07da24d46bcdd078ebebd7c6e6e3d750"): {common.BigToHash(big.NewInt(383)), common.BigToHash(big.NewInt(100000000))},
	//EverRise (RISE) 18
	common.HexToAddress("0x0cD022ddE27169b20895e0e2B2B8A33B25e63579"): {common.BigToHash(big.NewInt(10)), common.BigToHash(big.NewInt(1000000000000000000))},
	//RHOC (RHOC) 8
	common.HexToAddress("0x168296bb09e24a88805cb9c33356536b980d3fc5"): {common.BigToHash(big.NewInt(1026)), common.BigToHash(big.NewInt(100000000))},
	//BitMartToken (BMC) 18
	common.HexToAddress("0x986EE2B944c42D017F52Af21c4c69B84DBeA35d8"): {common.BigToHash(big.NewInt(3605)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Refereum (RFR) 4
	common.HexToAddress("0xd0929d411954c47438dc1d871dd6081f5c5e149c"): {common.BigToHash(big.NewInt(130)), common.BigToHash(big.NewInt(10000))},
	//MANTRA DAO (OM) 18
	common.HexToAddress("0x3593d125a4f7849a1b059e64f4517a86dd60c95d"): {common.BigToHash(big.NewInt(1509)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BOSAGORA (BOA) 7
	common.HexToAddress("0x746dda2ea243400d5a63e0700f190ab79f06489e"): {common.BigToHash(big.NewInt(2037)), common.BigToHash(big.NewInt(10000000))},
	//Metronome (MET) 18
	common.HexToAddress("0xa3d58c4e56fedcae3a7c43a725aee9a71f0ece4e"): {common.BigToHash(big.NewInt(50100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PolkaFoundry (PKF) 18
	common.HexToAddress("0x8b39b70e39aa811b69365398e0aace9bee238aeb"): {common.BigToHash(big.NewInt(16200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DGD (DGD) 9
	common.HexToAddress("0xe0b7927c4af23765cb51314a0e0521a9645f0e2a"): {common.BigToHash(big.NewInt(7595400)), common.BigToHash(big.NewInt(1000000000))},
	//Parsiq Token (PRQ) 18
	common.HexToAddress("0x362bc847A3a9637d3af6624EeC853618a43ed7D2"): {common.BigToHash(big.NewInt(4306)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Measurable Data Token (MDT) 18
	common.HexToAddress("0x814e0908b12a99fecf5bc101bb5d0b8b5cdf7d26"): {common.BigToHash(big.NewInt(1001)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Fusion (FSN) 18
	common.HexToAddress("0xd0352a019e9ab9d757776f532377aaebd36fd541"): {common.BigToHash(big.NewInt(7556)), common.BigToHash(big.NewInt(1000000000000000000))},
	//OCC (OCC) 18
	common.HexToAddress("0x2f109021afe75b949429fe30523ee7c0d5b27207"): {common.BigToHash(big.NewInt(31300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Marlin POND (POND) 18
	common.HexToAddress("0x57b946008913b82e4df85f501cbaed910e58d26c"): {common.BigToHash(big.NewInt(658)), common.BigToHash(big.NewInt(1000000000000000000))},
	//MATH Token (MATH) 18
	common.HexToAddress("0x08d967bb0134f2d07f7cfb6e246680c53927dd30"): {common.BigToHash(big.NewInt(3624)), common.BigToHash(big.NewInt(1000000000000000000))},
	//LockTrip (LOC) 18
	common.HexToAddress("0x5e3346444010135322268a4630d2ed5f8d09446c"): {common.BigToHash(big.NewInt(31600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Kryll (KRL) 18
	common.HexToAddress("0x464ebe77c293e473b48cfe96ddcf88fcf7bfdac0"): {common.BigToHash(big.NewInt(13700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Shyft [ Wrapped ] (SHFT) 18
	common.HexToAddress("0xb17c88bda07d28b3838e0c1de6a30eafbcf52d85"): {common.BigToHash(big.NewInt(3685)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Adshares (ADS) 11
	common.HexToAddress("0xcfcecfe2bd2fed07a9145222e8a7ad9cf1ccd22a"): {common.BigToHash(big.NewInt(24100)), common.BigToHash(big.NewInt(100000000000))},
	//AirSwap (AST) 4
	common.HexToAddress("0x27054b13b1b798b345b591a4d22e6562d47ea75a"): {common.BigToHash(big.NewInt(2938)), common.BigToHash(big.NewInt(10000))},
	//Dock (DOCK) 18
	common.HexToAddress("0xe5dada80aa6477e85d09747f2842f7993d0df71c"): {common.BigToHash(big.NewInt(678)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Hegic (HEGIC) 18
	common.HexToAddress("0x584bC13c7D411c00c01A62e8019472dE68768430"): {common.BigToHash(big.NewInt(711)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DEXTools (DEXT) 18
	common.HexToAddress("0xfb7b4564402e5500db5bb6d63ae671302777c75a"): {common.BigToHash(big.NewInt(4624)), common.BigToHash(big.NewInt(1000000000000000000))},
	//STAKE (STAKE) 18
	common.HexToAddress("0x0Ae055097C6d159879521C384F1D2123D1f195e6"): {common.BigToHash(big.NewInt(144700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pTokens BTC (pBTC) 18
	common.HexToAddress("0x5228a22e72ccc52d415ecfd199f99d0665e7733b"): {common.BigToHash(big.NewInt(490380000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SENTINEL PROTOCOL (UPP) 18
	common.HexToAddress("0xc86d054809623432210c107af2e3f619dcfbf652"): {common.BigToHash(big.NewInt(1487)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CoinDash Token (CDT) 18
	common.HexToAddress("0x177d39ac676ed1c67a2b268ad7f1e58826e5b0af"): {common.BigToHash(big.NewInt(712)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Sentivate (SNTVT) 18
	common.HexToAddress("0x7865af71cf0b288b4e7f654f4f7851eb46a2b7f8"): {common.BigToHash(big.NewInt(189)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Frontier Token (FRONT) 18
	common.HexToAddress("0xf8C3527CC04340b208C854E985240c02F7B7793f"): {common.BigToHash(big.NewInt(7044)), common.BigToHash(big.NewInt(1000000000000000000))},
	//QASH (QASH) 6
	common.HexToAddress("0x618e75ac90b12c6049ba3b27f5d5f8651b0037f6"): {common.BigToHash(big.NewInt(661)), common.BigToHash(big.NewInt(1000000))},
	//BTU Protocol (BTU) 18
	common.HexToAddress("0xb683d83a532e2cb7dfa5275eed3698436371cc9f"): {common.BigToHash(big.NewInt(5524)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Pinakion (PNK) 18
	common.HexToAddress("0x93ed3fbe21207ec2e8f2d3c3de6e058cb73bc04d"): {common.BigToHash(big.NewInt(817)), common.BigToHash(big.NewInt(1000000000000000000))},

	//Gifto (GTO) 5
	common.HexToAddress("0xc5bbae50781be1669306b9e001eff57a2957b09d"): {common.BigToHash(big.NewInt(597)), common.BigToHash(big.NewInt(100000))},
	//Nectar (NCT) 18
	common.HexToAddress("0x9e46a38f5daabe8683e10793b06749eef7d733d1"): {common.BigToHash(big.NewInt(253)), common.BigToHash(big.NewInt(1000000000000000000))},
	//NimiqNetwork (NET) 18
	common.HexToAddress("0xcfb98637bcae43C13323EAa1731cED2B716962fD"): {common.BigToHash(big.NewInt(45)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ERC20 (ERC20) 18
	common.HexToAddress("0xc3761eb917cd790b30dad99f6cc5b4ff93c4f9ea"): {common.BigToHash(big.NewInt(325)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PolkaBridge (PBR) 18
	common.HexToAddress("0x298d492e8c1d909d3f63bc4a36c66c64acb3d695"): {common.BigToHash(big.NewInt(9484)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Civilization (CIV) 18
	common.HexToAddress("0x37fe0f067fa808ffbdd12891c0858532cfe7361d"): {common.BigToHash(big.NewInt(1146)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SelfKey (KEY) 18
	common.HexToAddress("0x4cc19356f2d37338b9802aa8e8fc58b0373296e7"): {common.BigToHash(big.NewInt(121)), common.BigToHash(big.NewInt(1000000000000000000))},
	//veCRV-DAO yVault (yveCRV-DAO) 18
	common.HexToAddress("0xc5bddf9843308380375a611c18b50fb9341f502a"): {common.BigToHash(big.NewInt(24600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Blockchain Monster Coin (BCMC) 18
	common.HexToAddress("0x2BA8349123de45E931a8C8264c332E6e9CF593F9"): {common.BigToHash(big.NewInt(13700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Rubic (RBC) 18
	common.HexToAddress("0xa4eed63db85311e22df4473f87ccfc3dadcfa3e3"): {common.BigToHash(big.NewInt(3064)), common.BigToHash(big.NewInt(1000000000000000000))},
	//NAGA Coin (NGC) 18
	common.HexToAddress("0x72dd4b6bd852a3aa172be4d6c5a6dbec588cf131"): {common.BigToHash(big.NewInt(4211)), common.BigToHash(big.NewInt(1000000000000000000))},
	//UNIC (UNIC) 18
	common.HexToAddress("0x94e0bab2f6ab1f19f4750e42d7349f2740513ad5"): {common.BigToHash(big.NewInt(1103100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Student Coin (STC) 18
	common.HexToAddress("0x15b543e986b8c34074dfc9901136d9355a537e7e"): {common.BigToHash(big.NewInt(61)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pNetwork Token (PNT) 18
	common.HexToAddress("0x89Ab32156e46F46D02ade3FEcbe5Fc4243B9AAeD"): {common.BigToHash(big.NewInt(9521)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Fuse Token (FUSE) 18
	common.HexToAddress("0x970b9bb2c0444f5e81e9d0efb84c8ccdcdcaf84d"): {common.BigToHash(big.NewInt(2157)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BLOCKv (VEE) 18
	common.HexToAddress("0x340d2bde5eb28c1eed91b2f790723e3b160613b7"): {common.BigToHash(big.NewInt(97)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Guaranteed Entrance Token (GET) 18
	common.HexToAddress("0x8a854288a5976036a725879164ca3e91d30c6a1b"): {common.BigToHash(big.NewInt(20000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//VesperToken (VSP) 18
	common.HexToAddress("0x1b40183efb4dd766f11bda7a7c3ad8982e998421"): {common.BigToHash(big.NewInt(46100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Exeedme (XED) 18
	common.HexToAddress("0xee573a945b01b788b9287ce062a0cfc15be9fd86"): {common.BigToHash(big.NewInt(4017)), common.BigToHash(big.NewInt(1000000000000000000))},
	//StackOS (STACK) 18
	common.HexToAddress("0x56a86d648c435dc707c8405b78e2ae8eb4e60ba4"): {common.BigToHash(big.NewInt(1122)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Stratos Token (STOS) 18
	common.HexToAddress("0x08c32b0726c5684024ea6e141c50ade9690bbdcc"): {common.BigToHash(big.NewInt(13700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Quantstamp (QSP) 18
	common.HexToAddress("0x99ea4db9ee77acd40b119bd1dc4e33e1c070b80d"): {common.BigToHash(big.NewInt(419)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ELYSIA (EL) 18
	common.HexToAddress("0x2781246fe707bb15cee3e5ea354e2154a2877b16"): {common.BigToHash(big.NewInt(109)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Launchpool token (LPOOL) 18
	common.HexToAddress("0x6149c26cd2f7b5ccdb32029af817123f6e37df5b"): {common.BigToHash(big.NewInt(30700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Walton (WTC) 18
	common.HexToAddress("0xb7cb1c96db6b22b0d3d9536e0108d062bd488f74"): {common.BigToHash(big.NewInt(9947)), common.BigToHash(big.NewInt(1000000000000000000))},
	//MCDEX Token (MCB) 18
	common.HexToAddress("0x4e352cF164E64ADCBad318C3a1e222E9EBa4Ce42"): {common.BigToHash(big.NewInt(156521)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Reserve (RSV) 18
	common.HexToAddress("0x196f4727526eA7FB1e17b2071B3d8eAA38486988"): {common.BigToHash(big.NewInt(10016)), common.BigToHash(big.NewInt(1000000000000000000))},
	//UnFederalReserveToken (eRSDL) 18
	common.HexToAddress("0x5218E472cFCFE0b64A064F055B43b4cdC9EfD3A6"): {common.BigToHash(big.NewInt(764)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Dragon (DRGN) 18
	common.HexToAddress("0x419c4db4b9e25d6db2ad9691ccb832c8d9fda05e"): {common.BigToHash(big.NewInt(775)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Deri (DERI) 18
	common.HexToAddress("0xa487bf43cf3b10dffc97a9a744cbb7036965d3b9"): {common.BigToHash(big.NewInt(2154)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Cardstack (CARD) 18
	common.HexToAddress("0x954b890704693af242613edef1b603825afcd708"): {common.BigToHash(big.NewInt(94)), common.BigToHash(big.NewInt(1000000000000000000))},
	//AVT (AVT) 18
	common.HexToAddress("0x0d88ed6e74bbfd96b831231638b66c05571e824f"): {common.BigToHash(big.NewInt(33800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//HOPR Token (HOPR) 18
	common.HexToAddress("0xf5581dfefd8fb0e4aec526be659cfab1f8c781da"): {common.BigToHash(big.NewInt(2350)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CargoX (CXO) 18
	common.HexToAddress("0xb6ee9668771a79be7967ee29a63d4184f8097143"): {common.BigToHash(big.NewInt(1610)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Switcheo Token (SWTH) 8
	common.HexToAddress("0xb4371da53140417cbb3362055374b10d97e420bb"): {common.BigToHash(big.NewInt(154)), common.BigToHash(big.NewInt(100000000))},
	//SENTinel (SENT) 8
	common.HexToAddress("0xa44e5137293e855b1b7bc7e2c6f8cd796ffcb037"): {common.BigToHash(big.NewInt(133)), common.BigToHash(big.NewInt(100000000))},
	//Spice (SFI) 18
	common.HexToAddress("0xb753428af26e81097e7fd17f40c88aaa3e04902c"): {common.BigToHash(big.NewInt(3317100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DSLA (DSLA) 18
	common.HexToAddress("0x3affcca64c2a6f4e3b6bd9c64cd2c969efd1ecbe"): {common.BigToHash(big.NewInt(47)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Route (ROUTE) 18
	common.HexToAddress("0x16eccfdbb4ee1a85a33f3a9b21175cd7ae753db4"): {common.BigToHash(big.NewInt(35600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Polkamon (PMON) 18
	common.HexToAddress("0x1796ae0b0fa4862485106a0de9b654efe301d0b2"): {common.BigToHash(big.NewInt(82000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Populous (PPT) 8
	common.HexToAddress("0xd4fa1460f537bb9085d22c7bccb5dd450ef28e3a"): {common.BigToHash(big.NewInt(7068)), common.BigToHash(big.NewInt(100000000))},
	//Blockport (BPT) 18
	common.HexToAddress("0x327682779bab2bf4d1337e8974ab9de8275a7ca8"): {common.BigToHash(big.NewInt(3888)), common.BigToHash(big.NewInt(1000000000000000000))},
	//LikeCoin (LIKE) 18
	common.HexToAddress("0x02f61fd266da6e8b102d4121f5ce7b992640cf98"): {common.BigToHash(big.NewInt(246)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Klee Kai (KLEE) 9
	common.HexToAddress("0x382f0160c24f5c515a19f155bac14d479433a407"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//THORSwap Token (THOR) 18
	common.HexToAddress("0xa5f2211b9b8170f694421f2046281775e8468044"): {common.BigToHash(big.NewInt(11299)), common.BigToHash(big.NewInt(1000000000000000000))},
	//0chain (ZCN) 10
	common.HexToAddress("0xb9EF770B6A5e12E45983C5D80545258aA38F3B78"): {common.BigToHash(big.NewInt(5056)), common.BigToHash(big.NewInt(10000000000))},
	//Smart MFG (MFG) 18
	common.HexToAddress("0x6710c63432a2de02954fc0f851db07146a6c0312"): {common.BigToHash(big.NewInt(787)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Darwinia Network Native Token (RING) 18
	common.HexToAddress("0x9469d013805bffb7d3debe5e7839237e535ec483"): {common.BigToHash(big.NewInt(472)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Gelato Network Token (GEL) 18
	common.HexToAddress("0x15b7c0c907e4c6b9adaaaabc300c08991d6cea05"): {common.BigToHash(big.NewInt(23000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//O3 Swap Token (O3) 18
	common.HexToAddress("0xee9801669c6138e84bd50deb500827b776777d28"): {common.BigToHash(big.NewInt(6576)), common.BigToHash(big.NewInt(1000000000000000000))},

	//Ultiledger (ULT) 18
	common.HexToAddress("0xe884cc2795b9c45beeac0607da9539fd571ccf85"): {common.BigToHash(big.NewInt(120)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Yuan Chain New (YCC) 8
	common.HexToAddress("0x37e1160184f7dd29f00b78c050bf13224780b0b0"): {common.BigToHash(big.NewInt(45)), common.BigToHash(big.NewInt(100000000))},
	//NUM Token (NUM) 18
	common.HexToAddress("0x3496b523e5c00a4b4150d6721320cddb234c3079"): {common.BigToHash(big.NewInt(9269)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Internxt (INXT) 8
	common.HexToAddress("0x4a8f5f96d5436e43112c2fbc6a9f70da9e4e16d4"): {common.BigToHash(big.NewInt(200700)), common.BigToHash(big.NewInt(100000000))},
	//Cindicator (CND) 18
	common.HexToAddress("0xd4c435f5b09f855c3317c8524cb1f586e42795fa"): {common.BigToHash(big.NewInt(115)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BAX (BAX) 18
	common.HexToAddress("0x9a0242b7a33dacbe40edb927834f96eb39f8fbcb"): {common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SAN (SAN) 18
	common.HexToAddress("0x7c5a0ce9267ed19b22f8cae653f198e3e8daf098"): {common.BigToHash(big.NewInt(3439)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Pendle (PENDLE) 18
	common.HexToAddress("0x808507121b80c02388fad14726482e061b8da827"): {common.BigToHash(big.NewInt(2970)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ICONOMI (ICN) 18
	common.HexToAddress("0x888666CA69E0f178DED6D75b5726Cee99A87D698"): {common.BigToHash(big.NewInt(2167)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ZBToken (ZB) 18
	common.HexToAddress("0xbd0793332e9fb844a52a205a233ef27a5b34b927"): {common.BigToHash(big.NewInt(2858)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ZEON (ZEON) 18
	common.HexToAddress("0xe5b826ca2ca02f09c1725e9bd98d9a8874c30532"): {common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BZ (BZ) 18
	common.HexToAddress("0x4375e7ad8a01b8ec3ed041399f62d9cd120e0063"): {common.BigToHash(big.NewInt(1613)), common.BigToHash(big.NewInt(1000000000000000000))},
	//WPPToken (WPP) 18
	common.HexToAddress("0x1955d744F9435522Be508D1Ba60E3c12D0690B6A"): {common.BigToHash(big.NewInt(66)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DaTa eXchange Token (DTX) 18
	common.HexToAddress("0x765f0c16d1ddc279295c1a7c24b0883f62d33f75"): {common.BigToHash(big.NewInt(908)), common.BigToHash(big.NewInt(1000000000000000000))},
	//FOAM Token (FOAM) 18
	common.HexToAddress("0x4946fcea7c692606e8908002e55a582af44ac121"): {common.BigToHash(big.NewInt(566)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Meta (MTA) 18
	common.HexToAddress("0xa3BeD4E1c75D00fa6f4E5E6922DB7261B5E9AcD2"): {common.BigToHash(big.NewInt(7034)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Fractal Protocol Token (FCL) 18
	common.HexToAddress("0xf4d861575ecc9493420a3f5a14f85b13f0b50eb3"): {common.BigToHash(big.NewInt(1813)), common.BigToHash(big.NewInt(1000000000000000000))},
	//TokenClub Token (TCT) 18
	common.HexToAddress("0x4824a7b64e3966b0133f4f4ffb1b9d6beb75fff7"): {common.BigToHash(big.NewInt(343)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Curate (XCUR) 8
	common.HexToAddress("0xE1c7E30C42C24582888C758984f6e382096786bd"): {common.BigToHash(big.NewInt(23300)), common.BigToHash(big.NewInt(100000000))},
	//Gro DAO Token (GRO) 18
	common.HexToAddress("0x3ec8798b81485a254928b70cda1cf0a2bb0b74d7"): {common.BigToHash(big.NewInt(49900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Shopping.io (SPI) 18
	common.HexToAddress("0x9b02dd390a603add5c07f9fd9175b7dabe8d63b7"): {common.BigToHash(big.NewInt(214700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//TE-FOOD/TustChain (TONE) 18
	common.HexToAddress("0x2Ab6Bb8408ca3199B8Fa6C92d5b455F820Af03c4"): {common.BigToHash(big.NewInt(328)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Nerve Network (NVT) 8
	common.HexToAddress("0x7b6f71c8b123b38aa8099e0098bec7fbc35b8a13"): {common.BigToHash(big.NewInt(673)), common.BigToHash(big.NewInt(100000000))},
	//0xBitcoin Token (0xBTC) 8
	common.HexToAddress("0xb6ed7644c69416d67b522e20bc294a9a9b405b31"): {common.BigToHash(big.NewInt(23200)), common.BigToHash(big.NewInt(100000000))},
	//Imported GBYTE (GBYTE) 18
	common.HexToAddress("0x31f69de127c8a0ff10819c0955490a4ae46fcc2a"): {common.BigToHash(big.NewInt(221500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ArcBlock (ABT) 18
	common.HexToAddress("0xb98d4c97425d9908e66e53a6fdf673acca0be986"): {common.BigToHash(big.NewInt(1708)), common.BigToHash(big.NewInt(1000000000000000000))},
	//QRL (QRL) 8
	common.HexToAddress("0x697beac28b09e122c4332d163985e8a73121b97f"): {common.BigToHash(big.NewInt(2200)), common.BigToHash(big.NewInt(100000000))},
	//Lamden Tau (TAU) 18
	common.HexToAddress("0xc27a2f05fa577a83ba0fdb4c38443c0718356501"): {common.BigToHash(big.NewInt(1166)), common.BigToHash(big.NewInt(1000000000000000000))},
	//InsurAce (INSUR) 18
	common.HexToAddress("0x544c42fbb96b39b21df61cf322b5edc285ee7429"): {common.BigToHash(big.NewInt(9521)), common.BigToHash(big.NewInt(1000000000000000000))},
	//stakedETH (stETH) 18
	common.HexToAddress("0xdfe66b14d37c77f4e9b180ceb433d1b164f0281d"): {common.BigToHash(big.NewInt(2532400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//iQeon (IQN) 18
	common.HexToAddress("0x0db8d8b76bc361bacbb72e2c491e06085a97ab31"): {common.BigToHash(big.NewInt(29700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Raiden (RDN) 18
	common.HexToAddress("0x255aa6df07540cb5d3d297f0d0d4d84cb52bc8e6"): {common.BigToHash(big.NewInt(3169)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Dentacoin (Dentacoin) 0
	common.HexToAddress("0x08d32b0da63e2C3bcF8019c9c5d849d7a9d791e6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1))},
	//Amber (AMB) 18
	common.HexToAddress("0x4dc3643dbc642b72c158e7f3d2ff232df61cb6ce"): {common.BigToHash(big.NewInt(298)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PoolTogether (POOL) 18
	common.HexToAddress("0x0cec1a9154ff802e7934fc916ed7ca50bde6844e"): {common.BigToHash(big.NewInt(51500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//EligmaToken (ELI) 18
	common.HexToAddress("0xc7c03b8a3fc5719066e185ea616e87b88eba44a3"): {common.BigToHash(big.NewInt(637)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dHedge DAO Token (DHT) 18
	common.HexToAddress("0xca1207647Ff814039530D7d35df0e1Dd2e91Fa84"): {common.BigToHash(big.NewInt(7413)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Nebulas (NAS) 18
	common.HexToAddress("0x5d65D971895Edc438f465c17DB6992698a52318D"): {common.BigToHash(big.NewInt(3301)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Oraichain Token (ORAI) 18
	common.HexToAddress("0x4c11249814f11b9346808179cf06e71ac328c1b5"): {common.BigToHash(big.NewInt(67600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PIKA (PIKA) 18
	common.HexToAddress("0x60f5672a271c7e39e787427a18353ba59a4a3578"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//GoBlank Token (BLANK) 18
	common.HexToAddress("0x41a3dba3d677e573636ba691a70ff2d606c29666"): {common.BigToHash(big.NewInt(6661)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Offshift (XFT) 18
	common.HexToAddress("0xabe580e7ee158da464b51ee1a83ac0289622e6be"): {common.BigToHash(big.NewInt(32100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Antimatter.Finance Governance Token (MATTER) 18
	common.HexToAddress("0x9b99cca871be05119b2012fd4474731dd653febe"): {common.BigToHash(big.NewInt(4577)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Cashaa (CAS) 18
	common.HexToAddress("0xe8780b48bdb05f928697a5e8155f672ed91462f7"): {common.BigToHash(big.NewInt(174)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Tranche Finance (SLICE) 18
	common.HexToAddress("0x0aee8703d34dd9ae107386d3eff22ae75dd616d1"): {common.BigToHash(big.NewInt(8162)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Arcona Distribution Contract (ARCONA) 18
	common.HexToAddress("0x0f71b8de197a1c84d31de0f1fa7926c365f052b3"): {common.BigToHash(big.NewInt(9301)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Morpheus Infrastructure Token (MITx) 18
	common.HexToAddress("0x4a527d8fc13c5203ab24ba0944f4cb14658d1db6"): {common.BigToHash(big.NewInt(320)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DappRadar (RADAR) 18
	common.HexToAddress("0x44709a920fccf795fbc57baa433cc3dd53c44dbe"): {common.BigToHash(big.NewInt(329)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Covesting (COV) 18
	common.HexToAddress("0xADA86b1b313D1D5267E3FC0bB303f0A2b66D0Ea7"): {common.BigToHash(big.NewInt(7274)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BiFi (BiFi) 18
	common.HexToAddress("0x2791bfd60d232150bff86b39b7146c0eaaa2ba81"): {common.BigToHash(big.NewInt(535)), common.BigToHash(big.NewInt(1000000000000000000))},

	//ProBit Token (PROB) 18
	common.HexToAddress("0xfb559ce67ff522ec0b9ba7f5dc9dc7ef6c139803"): {common.BigToHash(big.NewInt(3516)), common.BigToHash(big.NewInt(1000000000000000000))},
	//RAE Token (RAE) 18
	common.HexToAddress("0xe5a3229ccb22b6484594973a03a3851dcd948756"): {common.BigToHash(big.NewInt(20000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Jenny Metaverse DAO Token (uJENNY) 18
	common.HexToAddress("0xa499648fd0e80fd911972bbeb069e4c20e68bf22"): {common.BigToHash(big.NewInt(13300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Cerby Token (CERBY) 18
	common.HexToAddress("0xdef1fac7bf08f173d286bbbdcbeeade695129840"): {common.BigToHash(big.NewInt(5)), common.BigToHash(big.NewInt(1000000000000000000))},
	//AnRKey X ($ANRX) 18
	common.HexToAddress("0xcae72a7a0fd9046cf6b165ca54c9e3a3872109e0"): {common.BigToHash(big.NewInt(1124)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Ethereans (OS) 18
	common.HexToAddress("0x6100dd79fcaa88420750dcee3f735d168abcb771"): {common.BigToHash(big.NewInt(235700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Atomic Wallet Token (AWC) 8
	common.HexToAddress("0xad22f63404f7305e4713ccbd4f296f34770513f4"): {common.BigToHash(big.NewInt(11620)), common.BigToHash(big.NewInt(100000000))},
	//ANGLE (ANGLE) 18
	common.HexToAddress("0x31429d1856ad1377a8a0079410b297e1a9e214c2"): {common.BigToHash(big.NewInt(3357)), common.BigToHash(big.NewInt(1000000000000000000))},
	//GOVI (GOVI) 18
	common.HexToAddress("0xeeaa40b28a2d1b0b08f6f97bb1dd4b75316c6107"): {common.BigToHash(big.NewInt(12249)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BTC 2x Flexible Leverage Index (BTC2x-FLI) 18
	common.HexToAddress("0x0b498ff89709d3838a063f1dfa463091f9801c2b"): {common.BigToHash(big.NewInt(453600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Lympo Market Token (LMT) 18
	common.HexToAddress("0x327673ae6b33bd3d90f0096870059994f30dc8af"): {common.BigToHash(big.NewInt(1598)), common.BigToHash(big.NewInt(1000000000000000000))},
	//UnmarshalToken (MARSH) 18
	common.HexToAddress("0x5a666c7d92e5fa7edcb6390e4efd6d0cdd69cf37"): {common.BigToHash(big.NewInt(5605)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Armor (ARMOR) 18
	common.HexToAddress("0x1337def16f9b486faed0293eb623dc8395dfe46a"): {common.BigToHash(big.NewInt(655)), common.BigToHash(big.NewInt(1000000000000000000))},
	//UTN-P: Universa Token (UTNP) 18
	common.HexToAddress("0x9e3319636e2126e3c0bc9e3134aec5e1508a46c7"): {common.BigToHash(big.NewInt(37)), common.BigToHash(big.NewInt(1000000000000000000))},
	//WaBi (WaBi) 18
	common.HexToAddress("0x286BDA1413a2Df81731D4930ce2F862a35A609fE"): {common.BigToHash(big.NewInt(1986)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Jarvis Reward Token (JRT) 18
	common.HexToAddress("0x8a9c67fee641579deba04928c4bc45f66e26343a"): {common.BigToHash(big.NewInt(548)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Knoxstertoken (FKX) 18
	common.HexToAddress("0x16484d73Ac08d2355F466d448D2b79D2039F6EBB"): {common.BigToHash(big.NewInt(758)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Geeq (GEEQ) 18
	common.HexToAddress("0x6B9f031D718dDed0d681c20cB754F97b3BB81b78"): {common.BigToHash(big.NewInt(9984)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Aurora (AOA) 18
	common.HexToAddress("0x9ab165d795019b6d8b3e971dda91071421305e5a"): {common.BigToHash(big.NewInt(26)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Genesis Pool (GPOOL) 18
	common.HexToAddress("0x797de1dc0b9faf5e25c1f7efe8df9599138fa09d"): {common.BigToHash(big.NewInt(317)), common.BigToHash(big.NewInt(1000000000000000000))},
	//OpenANX (OAX) 18
	common.HexToAddress("0x701c244b988a513c945973defa05de933b23fe1d"): {common.BigToHash(big.NewInt(1923)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Moeda Loyalty Points (MDA) 18
	common.HexToAddress("0x51db5ad35c671a87207d88fc11d593ac0c8415bd"): {common.BigToHash(big.NewInt(5633)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Salt (SALT) 8
	common.HexToAddress("0x4156D3342D5c385a87D264F90653733592000581"): {common.BigToHash(big.NewInt(1249)), common.BigToHash(big.NewInt(100000000))},
	//1-UP (1-UP) 18
	common.HexToAddress("0xc86817249634ac209bc73fca1712bbd75e37407d"): {common.BigToHash(big.NewInt(1813)), common.BigToHash(big.NewInt(1000000000000000000))},
	//KAN (KAN) 18
	common.HexToAddress("0x1410434b0346f5be678d0fb554e5c7ab620f8f4a"): {common.BigToHash(big.NewInt(20)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Plasma (PPAY) 18
	common.HexToAddress("0x054D64b73d3D8A21Af3D764eFd76bCaA774f3Bb2"): {common.BigToHash(big.NewInt(699)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Monetha (MTH) 5
	common.HexToAddress("0xaf4dce16da2877f8c9e00544c93b62ac40631f16"): {common.BigToHash(big.NewInt(304)), common.BigToHash(big.NewInt(100000))},
	//Free Coin (FREE) 18
	common.HexToAddress("0x2f141ce366a2462f02cea3d12cf93e4dca49e4fd"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Pluton (PLU) 18
	common.HexToAddress("0xD8912C10681D8B21Fd3742244f44658dBA12264E"): {common.BigToHash(big.NewInt(56700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CRPT (CRPT) 18
	common.HexToAddress("0x08389495d7456e1951ddf7c3a1314a4bfb646d8b"): {common.BigToHash(big.NewInt(1233)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Pinknode Token (PNODE) 18
	common.HexToAddress("0xaf691508ba57d416f895e32a1616da1024e882d2"): {common.BigToHash(big.NewInt(1082)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Strips Token (STRP) 18
	common.HexToAddress("0x97872eafd79940c7b24f7bcc1eadb1457347adc9"): {common.BigToHash(big.NewInt(38900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ZTCoin (ZT) 18
	common.HexToAddress("0xfe39e6a32acd2af7955cb3d406ba2b55c901f247"): {common.BigToHash(big.NewInt(203)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Monolith (TKN) 8
	common.HexToAddress("0xaaaf91d9b90df800df4f55c205fd6989c977e73a"): {common.BigToHash(big.NewInt(2736)), common.BigToHash(big.NewInt(100000000))},
	//Standard (STND) 18
	common.HexToAddress("0x9040e237c3bf18347bb00957dc22167d0f2b999d"): {common.BigToHash(big.NewInt(3536)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Tidal Token (TIDAL) 18
	common.HexToAddress("0x29cbd0510eec0327992cd6006e63f9fa8e7f33b7"): {common.BigToHash(big.NewInt(42)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Jigstack (STAK) 18
	common.HexToAddress("0x1f8a626883d7724dbd59ef51cbd4bf1cf2016d13"): {common.BigToHash(big.NewInt(84)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Furucombo (COMBO) 18
	common.HexToAddress("0xffffffff2ba8f66d4e51811c5190992176930278"): {common.BigToHash(big.NewInt(3955)), common.BigToHash(big.NewInt(1000000000000000000))},
	//LAtoken (LA) 18
	common.HexToAddress("0xe50365f5d679cb98a1dd62d6f6e58e59321bcddf"): {common.BigToHash(big.NewInt(1598)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Fair Token (FAIR) 18
	common.HexToAddress("0x9b20dabcec77f6289113e61893f7beefaeb1990a"): {common.BigToHash(big.NewInt(136)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Smart Advertising Transaction Token (SATT) 18
	common.HexToAddress("0xdf49c9f599a0a9049d97cff34d0c30e468987389"): {common.BigToHash(big.NewInt(22)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Digg (DIGG) 9
	common.HexToAddress("0x798d1be841a82a273720ce31c822c61a67a601c3"): {common.BigToHash(big.NewInt(376000000)), common.BigToHash(big.NewInt(1000000000))},
	//Float Bank (BANK) 18
	common.HexToAddress("0x24a6a37576377f63f194caa5f518a60f45b42921"): {common.BigToHash(big.NewInt(708400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Airbloc (ABL) 18
	common.HexToAddress("0xf8b358b3397a8ea5464f8cc753645d42e14b79ea"): {common.BigToHash(big.NewInt(337)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Unido (UDO) 18
	common.HexToAddress("0xea3983fc6d0fbbc41fb6f6091f68f3e08894dc06"): {common.BigToHash(big.NewInt(1286)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Lambda (LAMB) 18
	common.HexToAddress("0x8971f9fd7196e5cee2c1032b50f656855af7dd26"): {common.BigToHash(big.NewInt(60)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Origin Dollar (OUSD) 18
	common.HexToAddress("0x2a8e1e676ec238d8a992307b495b45b3feaa5e86"): {common.BigToHash(big.NewInt(9956)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SPANK (SPANK) 18
	common.HexToAddress("0x42d6622dece394b54999fbd73d108123806f6a18"): {common.BigToHash(big.NewInt(133)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DivergenceProtocol (DIVER) 18
	common.HexToAddress("0xfb782396c9b20e564a64896181c7ac8d8979d5f4"): {common.BigToHash(big.NewInt(1573)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Public Mint (MINT) 18
	common.HexToAddress("0x0cdf9acd87e940837ff21bb40c9fd55f68bba059"): {common.BigToHash(big.NewInt(1207)), common.BigToHash(big.NewInt(1000000000000000000))},

	//Float Bank (BANK) 18
	common.HexToAddress("0x24a6a37576377f63f194caa5f518a60f45b42921"): {common.BigToHash(big.NewInt(707600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Airbloc (ABL) 18
	common.HexToAddress("0xf8b358b3397a8ea5464f8cc753645d42e14b79ea"): {common.BigToHash(big.NewInt(335)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Unido (UDO) 18
	common.HexToAddress("0xea3983fc6d0fbbc41fb6f6091f68f3e08894dc06"): {common.BigToHash(big.NewInt(1286)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Lambda (LAMB) 18
	common.HexToAddress("0x8971f9fd7196e5cee2c1032b50f656855af7dd26"): {common.BigToHash(big.NewInt(60)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Origin Dollar (OUSD) 18
	common.HexToAddress("0x2a8e1e676ec238d8a992307b495b45b3feaa5e86"): {common.BigToHash(big.NewInt(9956)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SPANK (SPANK) 18
	common.HexToAddress("0x42d6622dece394b54999fbd73d108123806f6a18"): {common.BigToHash(big.NewInt(133)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DivergenceProtocol (DIVER) 18
	common.HexToAddress("0xfb782396c9b20e564a64896181c7ac8d8979d5f4"): {common.BigToHash(big.NewInt(1573)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Public Mint (MINT) 18
	common.HexToAddress("0x0cdf9acd87e940837ff21bb40c9fd55f68bba059"): {common.BigToHash(big.NewInt(1207)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PCHAIN (PAI) 18
	common.HexToAddress("0xb9bb08ab7e9fa0a1356bd4a39ec0ca267e03b0b3"): {common.BigToHash(big.NewInt(103)), common.BigToHash(big.NewInt(1000000000000000000))},
	//SwftCoin (SWFTC) 8
	common.HexToAddress("0x0bb217e40f8a5cb79adf04e1aab60e5abd0dfc1e"): {common.BigToHash(big.NewInt(13)), common.BigToHash(big.NewInt(100000000))},
	//Wirex Token (WXT) 18
	common.HexToAddress("0xa02120696c7b8fe16c09c749e4598819b2b0e915"): {common.BigToHash(big.NewInt(36)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Voice Token (VOICE) 18
	common.HexToAddress("0x2e2364966267B5D7D2cE6CD9A9B5bD19d9C7C6A9"): {common.BigToHash(big.NewInt(2316300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Rupiah Token (IDRT) 2
	common.HexToAddress("0x998FFE1E43fAcffb941dc337dD0468d52bA5b48A"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(100))},
	//Compound Wrapped BTC (cWBTC) 8
	common.HexToAddress("0xC11b1268C1A384e55C48c2391d8d480264A3A7F4"): {common.BigToHash(big.NewInt(9811400)), common.BigToHash(big.NewInt(100000000))},
	//Decentr (DEC) 18
	common.HexToAddress("0x30f271C9E86D2B7d00a6376Cd96A1cFBD5F0b9b3"): {common.BigToHash(big.NewInt(801)), common.BigToHash(big.NewInt(1000000000000000000))},
	//TrueFlip (TFL) 8
	common.HexToAddress("0xa7f976c360ebbed4465c2855684d1aae5271efa9"): {common.BigToHash(big.NewInt(11800)), common.BigToHash(big.NewInt(100000000))},
	//VIB (VIB) 18
	common.HexToAddress("0x2C974B2d0BA1716E644c1FC59982a89DDD2fF724"): {common.BigToHash(big.NewInt(429)), common.BigToHash(big.NewInt(1000000000000000000))},
	//QuadrantProtocol (eQUAD) 18
	common.HexToAddress("0xc28e931814725bbeb9e670676fabbcb694fe7df2"): {common.BigToHash(big.NewInt(141)), common.BigToHash(big.NewInt(1000000000000000000))},
	//StakeWise (SWISE) 18
	common.HexToAddress("0x48c3399719b582dd63eb5aadf12a40b4c3f52fa2"): {common.BigToHash(big.NewInt(1183)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Dapp Token (DAPPT) 18
	common.HexToAddress("0x96184d9C811Ea0624fC30C80233B1d749B9E485B"): {common.BigToHash(big.NewInt(52)), common.BigToHash(big.NewInt(1000000000000000000))},
	//BHPCash (BHPC) 18
	common.HexToAddress("0xee74110fb5a1007b06282e0de5d73a61bf41d9cd"): {common.BigToHash(big.NewInt(3641)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Vibe Coin (VIBE) 18
	common.HexToAddress("0xe8ff5c9c75deb346acac493c463c8950be03dfba"): {common.BigToHash(big.NewInt(391)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Leverj Gluon (L2) 18
	common.HexToAddress("0xbbff34e47e559ef680067a6b1c980639eeb64d24"): {common.BigToHash(big.NewInt(250)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Falcon (FNT) 6
	common.HexToAddress("0xdc5864ede28bd4405aa04d93e05a0531797d9d59"): {common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(1000000))},
	//Ixs Token (IXS) 18
	common.HexToAddress("0x73d7c860998ca3c01ce8c808f5577d94d545d1b4"): {common.BigToHash(big.NewInt(1849)), common.BigToHash(big.NewInt(1000000000000000000))},
	//UREEQA Token (URQA) 18
	common.HexToAddress("0x1735db6ab5baa19ea55d0adceed7bcdc008b3136"): {common.BigToHash(big.NewInt(1733)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PieDAO DOUGH v2 (DOUGH) 18
	common.HexToAddress("0xad32A8e6220741182940c5aBF610bDE99E737b2D"): {common.BigToHash(big.NewInt(4552)), common.BigToHash(big.NewInt(1000000000000000000))},
	//AurusDeFi (AWX) 18
	common.HexToAddress("0xa51fc71422a30fa7ffa605b360c3b283501b5bf6"): {common.BigToHash(big.NewInt(21100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//NFT INDEX (NFTI) 18
	common.HexToAddress("0xe5feeac09d36b18b3fa757e5cf3f8da6b8e27f4c"): {common.BigToHash(big.NewInt(30077118)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Enigma (ENG) 8
	common.HexToAddress("0xf0ee6b27b759c9893ce4f094b49ad28fd15a23e4"): {common.BigToHash(big.NewInt(803)), common.BigToHash(big.NewInt(100000000))},
	//AMLT (AMLT) 18
	common.HexToAddress("0xca0e7269600d353f70b14ad118a49575455c0f2f"): {common.BigToHash(big.NewInt(196)), common.BigToHash(big.NewInt(1000000000000000000))},
	//YUKI (YUKI) 8
	common.HexToAddress("0x5ab793e36070f0fac928ea15826b0c1bc5365119"): {common.BigToHash(big.NewInt(5)), common.BigToHash(big.NewInt(100000000))},
	//Tierion Network Token (TNT) 8
	common.HexToAddress("0x08f5a9235b08173b7569f83645d2c7fb55e8ccd8"): {common.BigToHash(big.NewInt(152)), common.BigToHash(big.NewInt(100000000))},
	//SpaceChain (SPC) 18
	common.HexToAddress("0x8069080a922834460c3a092fb2c1510224dc066b"): {common.BigToHash(big.NewInt(158)), common.BigToHash(big.NewInt(1000000000000000000))},
	//TOKPIE (TKP) 18
	common.HexToAddress("0xd31695a1d35e489252ce57b129fd4b1b05e6acac"): {common.BigToHash(big.NewInt(806)), common.BigToHash(big.NewInt(1000000000000000000))},
	//MATRIX AI Network (MAN) 18
	common.HexToAddress("0xe25bcec5d3801ce3a794079bf94adf1b8ccd802d"): {common.BigToHash(big.NewInt(424)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Tokenomy (TEN) 18
	common.HexToAddress("0xdd16ec0f66e54d453e6756713e533355989040e4"): {common.BigToHash(big.NewInt(538)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Coinvest COIN V3 Token (COIN) 18
	common.HexToAddress("0xeb547ed1D8A3Ff1461aBAa7F0022FED4836E00A4"): {common.BigToHash(big.NewInt(1963)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Yee - A Blockchain-powered &amp; Cloud-based Socia (YEE) 18
	common.HexToAddress("0x922105fad8153f516bcfb829f56dc097a0e1d705"): {common.BigToHash(big.NewInt(20)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Blockchain Certified Data Token (BCDT) 18
	common.HexToAddress("0xacfa209fb73bf3dd5bbfb1101b9bc999c49062a5"): {common.BigToHash(big.NewInt(1648)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Everex (EVX) 4
	common.HexToAddress("0xf3db5fa2c66b7af3eb0c0b782510816cbe4813b8"): {common.BigToHash(big.NewInt(2746)), common.BigToHash(big.NewInt(10000))},
	//TenXPay (PAY) 18
	common.HexToAddress("0xB97048628DB6B661D4C2aA833e95Dbe1A905B280"): {common.BigToHash(big.NewInt(508)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Pawthereum (PAWTH) 9
	common.HexToAddress("0xaecc217a749c2405b5ebc9857a16d58bdc1c367f"): {common.BigToHash(big.NewInt(85)), common.BigToHash(big.NewInt(1000000000))},
	//RipioCreditNetwork (RCN) 18
	common.HexToAddress("0xf970b8e36e23f7fc3fd752eea86f8be8d83375a6"): {common.BigToHash(big.NewInt(109)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Bloom (BLT) 18
	common.HexToAddress("0x107c4504cd79c5d2696ea0030a8dd4e92601b82e"): {common.BigToHash(big.NewInt(1018)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Insights Network (INSTAR) 18
	common.HexToAddress("0xc72fe8e3dd5bef0f9f31f259399f301272ef2a2d"): {common.BigToHash(big.NewInt(291)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ChangeNOW (NOW) 8
	common.HexToAddress("0xe9a95d175a5f4c9369f3b74222402eb1b837693b"): {common.BigToHash(big.NewInt(683)), common.BigToHash(big.NewInt(100000000))},
	//CREDITS (CS) 6
	common.HexToAddress("0x46b9ad944d1059450da1163511069c718f699d31"): {common.BigToHash(big.NewInt(253)), common.BigToHash(big.NewInt(1000000))},
	//XIO Network (XIO) 18
	common.HexToAddress("0x0f7F961648aE6Db43C75663aC7E5414Eb79b5704"): {common.BigToHash(big.NewInt(1454)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DOVU (DOV) 18
	common.HexToAddress("0xac3211a5025414af2866ff09c23fc18bc97e79b1"): {common.BigToHash(big.NewInt(176)), common.BigToHash(big.NewInt(1000000000000000000))},

	//Hakka Finance (HAKKA) 18
	common.HexToAddress("0x0E29e5AbbB5FD88e28b2d355774e73BD47dE3bcd"): {common.BigToHash(big.NewInt(183)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Internet Node Token (INT) 6
	common.HexToAddress("0x0b76544f6c413a555f309bf76260d1e02377c02a"): {common.BigToHash(big.NewInt(109)), common.BigToHash(big.NewInt(1000000))},
	//BIXToken (BIX) 18
	common.HexToAddress("0x009c43b42aefac590c719e971020575974122803"): {common.BigToHash(big.NewInt(442)), common.BigToHash(big.NewInt(1000000000000000000))},
	//TOP Network (TOP) 18
	common.HexToAddress("0xdcd85914b8ae28c1e62f1c488e1d968d5aaffe2b"): {common.BigToHash(big.NewInt(9)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Matryx (MTX) 18
	common.HexToAddress("0x0af44e2784637218dd1d32a322d44e603a8f0c6a"): {common.BigToHash(big.NewInt(2102)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CAPP Token (CAPP) 2
	common.HexToAddress("0x11613b1f840bb5A40F8866d857e24DA126B79D73"): {common.BigToHash(big.NewInt(73)), common.BigToHash(big.NewInt(100))},
	//Cappasity (CAPP) 2
	common.HexToAddress("0x04f2e7221fdb1b52a68169b25793e51478ff0329"): {common.BigToHash(big.NewInt(73)), common.BigToHash(big.NewInt(100))},
	//Revain (REV) 6
	common.HexToAddress("0x2ef52Ed7De8c5ce03a4eF0efbe9B7450F2D7Edc9"): {common.BigToHash(big.NewInt(99)), common.BigToHash(big.NewInt(1000000))},
	//ZMINE Token (ZMN) 18
	common.HexToAddress("0x554ffc77f4251a9fb3c0e3590a6a205f8d4e067d"): {common.BigToHash(big.NewInt(78)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Hiveterminal Token (HVN) 8
	common.HexToAddress("0xC0Eb85285d83217CD7c891702bcbC0FC401E2D9D"): {common.BigToHash(big.NewInt(132)), common.BigToHash(big.NewInt(100000000))},
	//AppCoins (APPC) 18
	common.HexToAddress("0x1a7a8bd9106f2b8d977e08582dc7d24c723ab0db"): {common.BigToHash(big.NewInt(400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Impermax (IMX) 18
	common.HexToAddress("0x7b35ce522cb72e4077baeb96cb923a5529764a00"): {common.BigToHash(big.NewInt(2016)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ClinTex (CTI) 18
	common.HexToAddress("0x8c18D6a985Ef69744b9d57248a45c0861874f244"): {common.BigToHash(big.NewInt(558)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CyberMiles (CMT) 18
	common.HexToAddress("0xf85feea2fdd81d51177f6b8f35f0e6734ce45f5f"): {common.BigToHash(big.NewInt(57)), common.BigToHash(big.NewInt(1000000000000000000))},
	//indaHash Coin (IDH) 6
	common.HexToAddress("0x5136c98a80811c3f46bdda8b5c4555cfd9f812f0"): {common.BigToHash(big.NewInt(138)), common.BigToHash(big.NewInt(1000000))},
	//Herocoin (PLAY) 18
	common.HexToAddress("0xe477292f1b3268687a29376116b0ed27a9c76170"): {common.BigToHash(big.NewInt(305)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Spendcoin (SPND) 18
	common.HexToAddress("0xddd460bbd9f79847ea08681563e8a9696867210c"): {common.BigToHash(big.NewInt(47)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ODEM Token (ODEM) 18
	common.HexToAddress("0xbf52f2ab39e26e0951d2a02b49b7702abe30406a"): {common.BigToHash(big.NewInt(201)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Carbon (CRBN) 18
	common.HexToAddress("0xCdeee767beD58c5325f68500115d4B722b3724EE"): {common.BigToHash(big.NewInt(1369)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Float Protocol: FLOAT (FLOAT) 18
	common.HexToAddress("0xb05097849bca421a3f51b249ba6cca4af4b97cb9"): {common.BigToHash(big.NewInt(16299)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PILLAR (PLR) 18
	common.HexToAddress("0xe3818504c1b32bf1557b16c238b2e01fd3149c17"): {common.BigToHash(big.NewInt(172)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Genaro X (GNX) 9
	common.HexToAddress("0x6ec8a24cabdc339a06a172f8223ea557055adaa5"): {common.BigToHash(big.NewInt(146)), common.BigToHash(big.NewInt(1000000000))},
	//GHOST (GHOST) 18
	common.HexToAddress("0x4c327471C44B2dacD6E90525f9D629bd2e4f662C"): {common.BigToHash(big.NewInt(2548)), common.BigToHash(big.NewInt(1000000000000000000))},
	//NapoleonX (NPX) 2
	common.HexToAddress("0x28b5e12cce51f15594b0b91d5b5adaa70f684a02"): {common.BigToHash(big.NewInt(1708)), common.BigToHash(big.NewInt(100))},
	//Bundles (BUND) 18
	common.HexToAddress("0x8D3E855f3f55109D473735aB76F753218400fe96"): {common.BigToHash(big.NewInt(504600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Woofy (WOOFY) 12
	common.HexToAddress("0xd0660cd418a64a1d44e9214ad8e459324d8157f1"): {common.BigToHash(big.NewInt(346)), common.BigToHash(big.NewInt(1000000000000))},
	//QunQunCommunities (QUN) 18
	common.HexToAddress("0x264dc2dedcdcbb897561a57cba5085ca416fb7b4"): {common.BigToHash(big.NewInt(63)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Edgeless (EDG) 0
	common.HexToAddress("0x08711d3b02c8758f2fb3ab4e80228418a7f8e39c"): {common.BigToHash(big.NewInt(368)), common.BigToHash(big.NewInt(1))},
	//Compound Sai (cSAI) 8
	common.HexToAddress("0xf5dce57282a584d2746faf1593d3121fcac444dc"): {common.BigToHash(big.NewInt(5097)), common.BigToHash(big.NewInt(100000000))},
	//HPBCoin (HPB) 18
	common.HexToAddress("0x38c6a68304cdefb9bec48bbfaaba5c5b47818bb2"): {common.BigToHash(big.NewInt(1078)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Block-Chain.com Token (BC) 18
	common.HexToAddress("0x2ecb13a8c458c379c4d9a7259e202de03c8f3d19"): {common.BigToHash(big.NewInt(198)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CryptalDash (CRD) 18
	common.HexToAddress("0xcaaa93712bdac37f736c323c93d4d5fdefcc31cc"): {common.BigToHash(big.NewInt(40)), common.BigToHash(big.NewInt(1000000000000000000))},
	//VeriSafe (VSF) 18
	common.HexToAddress("0xac9ce326e95f51b5005e9fe1dd8085a01f18450c"): {common.BigToHash(big.NewInt(5)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cVToken (cV) 18
	common.HexToAddress("0x50bC2Ecc0bfDf5666640048038C1ABA7B7525683"): {common.BigToHash(big.NewInt(5)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Egretia (EGT) 18
	common.HexToAddress("0x8e1b448ec7adfc7fa35fc2e885678bd323176e34"): {common.BigToHash(big.NewInt(10)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Signata (SATA) 18
	common.HexToAddress("0x3ebb4a4e91ad83be51f8d596533818b246f4bee1"): {common.BigToHash(big.NewInt(1945)), common.BigToHash(big.NewInt(1000000000000000000))},
	//HitchainCoin (HIT) 6
	common.HexToAddress("0x7995ab36bb307afa6a683c24a25d90dc1ea83566"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000))},
	//ZAP TOKEN (ZAP) 18
	common.HexToAddress("0x6781a0f84c7e9e846dcb84a9a5bd49333067b104"): {common.BigToHash(big.NewInt(151)), common.BigToHash(big.NewInt(1000000000000000000))},
	//PumaPay (PMA) 18
	common.HexToAddress("0x846c66cf71c43f80403b51fe3906b3599d63336f"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nDEX (NDX) 18
	common.HexToAddress("0x1966d718a565566e8e202792658d7b5ff4ece469"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Simple Token (ST) 18
	common.HexToAddress("0x2c4e8f2d746113d0696ce89b35f0d8bf88e0aeca"): {common.BigToHash(big.NewInt(53)), common.BigToHash(big.NewInt(1000000000000000000))},
	//RED MWAT (MWAT) 18
	common.HexToAddress("0x6425c6be902d692ae2db752b3c268afadb099d3b"): {common.BigToHash(big.NewInt(79)), common.BigToHash(big.NewInt(1000000000000000000))},
	//CUBE (AUTO) 18
	common.HexToAddress("0x622dFfCc4e83C64ba959530A5a5580687a57581b"): {common.BigToHash(big.NewInt(5)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Public Index Network (PIN) 18
	common.HexToAddress("0xc1f976b91217e240885536af8b63bc8b5269a9be"): {common.BigToHash(big.NewInt(225)), common.BigToHash(big.NewInt(1000000000000000000))},
	//https://unimex.network/ (UMX) 18
	common.HexToAddress("0x10be9a8dae441d276a5027936c3aaded2d82bc15"): {common.BigToHash(big.NewInt(4719)), common.BigToHash(big.NewInt(1000000000000000000))},
	//DOS Network Token (DOS) 18
	common.HexToAddress("0x0A913beaD80F321E7Ac35285Ee10d9d922659cB7"): {common.BigToHash(big.NewInt(265)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Tadpole (TAD) 18
	common.HexToAddress("0x9f7229aF0c4b9740e207Ea283b9094983f78ba04"): {common.BigToHash(big.NewInt(85200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Shadows Network (DOWS) 18
	common.HexToAddress("0x661ab0ed68000491d98c796146bcf28c20d7c559"): {common.BigToHash(big.NewInt(1297)), common.BigToHash(big.NewInt(1000000000000000000))},
	//Quantum (QAU) 8
	common.HexToAddress("0x671abbe5ce652491985342e85428eb1b07bc6c64"): {common.BigToHash(big.NewInt(455)), common.BigToHash(big.NewInt(100000000))},
	//LGO Token (LGO) 8
	common.HexToAddress("0x0a50c93c762fdd6e56d86215c24aaad43ab629aa"): {common.BigToHash(big.NewInt(208)), common.BigToHash(big.NewInt(100000000))},

	//usd-coin 6
	common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"): {common.BigToHash(big.NewInt(10100)), common.BigToHash(big.NewInt(1000000))},
	//multi-collateral-dai 18
	common.HexToAddress("0x6b175474e89094c44da98b954eedeac495271d0f"): {common.BigToHash(big.NewInt(10100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//weth 18
	common.HexToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"): {common.BigToHash(big.NewInt(32149100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fei-usd 18
	common.HexToAddress("0x956F47F50A910163D8BF957Cf5846D573E7f87CA"): {common.BigToHash(big.NewInt(9978)), common.BigToHash(big.NewInt(1000000000000000000))},
	//frax-share 18
	common.HexToAddress("0x3432b6a60d23ca0dfca7761b7ab56459d9c964d0"): {common.BigToHash(big.NewInt(382100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//vader-protocol 18
	common.HexToAddress("0x2602278ee1882889b946eb11dc0e810075650983"): {common.BigToHash(big.NewInt(811)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tokemak 18
	common.HexToAddress("0x2e9d63788249371f1DFC918a52f8d799F4a38C94"): {common.BigToHash(big.NewInt(586900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//saitama-inu 9
	common.HexToAddress("0x8b3192f5eebd8579568a2ed41e6feb402f93f73f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//strong 18
	common.HexToAddress("0x990f341946a3fdb507ae7e52d17851b87168017c"): {common.BigToHash(big.NewInt(6213000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fuse-network 18
	common.HexToAddress("0x970b9bb2c0444f5e81e9d0efb84c8ccdcdcaf84d"): {common.BigToHash(big.NewInt(12800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hex 8
	common.HexToAddress("0x2b591e99afe9f32eaa6214f7b7629768c40eeb39"): {common.BigToHash(big.NewInt(2250)), common.BigToHash(big.NewInt(100000000))},
	//the-sandbox 18
	common.HexToAddress("0x3845badAde8e6dFF049820680d1F14bD3903a5d0"): {common.BigToHash(big.NewInt(49300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chainlink 18
	common.HexToAddress("0x514910771af9ca656af840dff83e8264ecf986ca"): {common.BigToHash(big.NewInt(262700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//synapse-2 18
	common.HexToAddress("0x0f2D719407FdBeFF09D87557AbB7232601FD9F29"): {common.BigToHash(big.NewInt(28800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//merit-circle 18
	common.HexToAddress("0x949d48eca67b17269629c7194f4b727d4ef9e5d6"): {common.BigToHash(big.NewInt(39700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//avocado-dao-token 18
	common.HexToAddress("0xa41f142b6eb2b164f8164cae0716892ce02f311f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//floki-inu 9
	common.HexToAddress("0x43f11c02439e2736800433b4594994Bd43Cd066D"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000))},
	//refi 18
	common.HexToAddress("0xA808B22ffd2c472aD1278088F16D4010E6a54D5F"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wrapped-bitcoin 8
	common.HexToAddress("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"): {common.BigToHash(big.NewInt(423000000)), common.BigToHash(big.NewInt(100000000))},
	//dogelon 18
	common.HexToAddress("0x761d38e5ddf6ccf6cf7c55759d5210750b5d60f3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wootrade 18
	common.HexToAddress("0x4691937a7508860f876c9c0a2a617e7d9e945d4b"): {common.BigToHash(big.NewInt(9618)), common.BigToHash(big.NewInt(1000000000000000000))},
	//depo 18
	common.HexToAddress("0xa5def515cfd373d17830e7c1de1639cb3530a112"): {common.BigToHash(big.NewInt(1671)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sushiswap 18
	common.HexToAddress("0x6b3595068778dd592e39a122f4f5a5cf09c90fe2"): {common.BigToHash(big.NewInt(71600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//star-link 18
	common.HexToAddress("0x8e6cd950ad6ba651f6dd608dc70e5886b1aa6b24"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//derace 18
	common.HexToAddress("0x9fa69536d1cda4a04cfb50688294de75b505a9ae"): {common.BigToHash(big.NewInt(24969)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ufo-gaming 18
	common.HexToAddress("0x249e38ea4102d0cf8264d3701f1a0e39c4f2dc3b"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//metisdao 18
	common.HexToAddress("0x9E32b13ce7f2E80A01932B42553652E053D6ed8e"): {common.BigToHash(big.NewInt(1728269)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ribbon-finance 18
	common.HexToAddress("0x6123b0049f904d730db3c36a31167d9d4121fa6b"): {common.BigToHash(big.NewInt(30000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//uniswap 18
	common.HexToAddress("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"): {common.BigToHash(big.NewInt(159600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//muse 18
	common.HexToAddress("0xb6ca7399b4f9ca56fc27cbff44f4d2e4eef1fc81"): {common.BigToHash(big.NewInt(462209)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rai 18
	common.HexToAddress("0x03ab458634910aad20ef5f1c8ee96f1d6ac54919"): {common.BigToHash(big.NewInt(30700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yearn-finance 18
	common.HexToAddress("0x0bc529c00c6401aef6d220be8c6ea1667f6ad93e"): {common.BigToHash(big.NewInt(358690000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sipher 18
	common.HexToAddress("0x9F52c8ecbEe10e00D9faaAc5Ee9Ba0fF6550F511"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//reflexer-ungovernance-token 18
	common.HexToAddress("0x6243d8cea23066d098a15582d81a598b4e8391f4"): {common.BigToHash(big.NewInt(3582939)), common.BigToHash(big.NewInt(1000000000000000000))},
	//uma 18
	common.HexToAddress("0x04Fa0d235C4abf4BcF4787aF4CF447DE572eF828"): {common.BigToHash(big.NewInt(95600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//constitutiondao 18
	common.HexToAddress("0x7a58c0be72be218b41c608b7fe7c5bb630736c71"): {common.BigToHash(big.NewInt(1019)), common.BigToHash(big.NewInt(1000000000000000000))},
	//vlaunch 18
	common.HexToAddress("0x51fe2e572e97bfeb1d719809d743ec2675924edc"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ojamu 18
	common.HexToAddress("0x0aa7efe4945db24d95ca6e117bba65ed326e291a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//quant 18
	common.HexToAddress("0x4a220e6096b25eadb88358cb44068a3248254675"): {common.BigToHash(big.NewInt(1803300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//aragon 18
	common.HexToAddress("0xa117000000f279d81a1d3cc75430faa017fa5a2e"): {common.BigToHash(big.NewInt(93500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xmon 18
	common.HexToAddress("0x3aaDA3e213aBf8529606924d8D1c55CbDc70Bf74"): {common.BigToHash(big.NewInt(501920000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//vesper 18
	common.HexToAddress("0x1b40183efb4dd766f11bda7a7c3ad8982e998421"): {common.BigToHash(big.NewInt(51800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//highstreet 18
	common.HexToAddress("0x71Ab77b7dbB4fa7e017BC15090b2163221420282"): {common.BigToHash(big.NewInt(93300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wilder-world 18
	common.HexToAddress("0x2a3bff78b79a009976eea096a51a948a3dc00e34"): {common.BigToHash(big.NewInt(22982)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shibnobi 9
	common.HexToAddress("0xab167e816e4d76089119900e941befdfa37d6b32"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//sidus-heroes-sidus-token 18
	common.HexToAddress("0x549020a9Cb845220D66d3E9c6D9F9eF61C981102"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//olympus 9
	common.HexToAddress("0x64aa3364f17a4d01c6f1751fd97c2bd3d7e7f1d5"): {common.BigToHash(big.NewInt(2678700)), common.BigToHash(big.NewInt(1000000000))},
	//brainiac-farm 18
	common.HexToAddress("0x39317b8a1ae06c30bb615d88cdc5522781499f1c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//aave 18
	common.HexToAddress("0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9"): {common.BigToHash(big.NewInt(2170560)), common.BigToHash(big.NewInt(1000000000000000000))},
	//impactxp 9
	common.HexToAddress("0xb12494c8824fc069757f47d177e666c571cd49ae"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//pax-gold 18
	common.HexToAddress("0x45804880de22913dafe09f4980848ece6ecbaf78"): {common.BigToHash(big.NewInt(18102900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lets-go-brandon 18
	common.HexToAddress("0x21e783bcf445b515957a10e992ad3c8e9ff51288"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shiba-inu 18
	common.HexToAddress("0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wrapped-luna-token 18
	common.HexToAddress("0xd2877702675e6ceb975b4a1dff9fb7baf4c91ea9"): {common.BigToHash(big.NewInt(698292)), common.BigToHash(big.NewInt(1000000000000000000))},
	//meta-capital 9
	common.HexToAddress("0xbce0665b20164d6cd6d15e70fed1e094ad4a44f0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//unfederalreserve 18
	common.HexToAddress("0x5218E472cFCFE0b64A064F055B43b4cdC9EfD3A6"): {common.BigToHash(big.NewInt(383)), common.BigToHash(big.NewInt(1000000000000000000))},
	//urus 18
	common.HexToAddress("0x6c5fbc90e4d78f70cc5025db005b39b03914fc0c"): {common.BigToHash(big.NewInt(692800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//eqifi 18
	common.HexToAddress("0xbd3de9a069648c84d27d74d701c9fa3253098b15"): {common.BigToHash(big.NewInt(3630)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mute 18
	common.HexToAddress("0xa49d7499271ae71cd8ab9ac515e6694c755d400c"): {common.BigToHash(big.NewInt(16210)), common.BigToHash(big.NewInt(1000000000000000000))},
	//aggregatedfinance 9
	common.HexToAddress("0x0be4447860ddf283884bbaa3702749706750b09e"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//decentraland 18
	common.HexToAddress("0x0f5d2fb29fb7d3cfee444a200298f468908cc942"): {common.BigToHash(big.NewInt(30896)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shibadoge 9
	common.HexToAddress("0x6adb2e268de2aa1abf6578e4a8119b960e02928f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//fantom 18
	common.HexToAddress("0x4e15361fd6b4bb609fa63c81a2be19d873717870"): {common.BigToHash(big.NewInt(26200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defi-pulse-index 18
	common.HexToAddress("0x1494ca1f11d487c2bbe4543e90080aeba4ba3c2b"): {common.BigToHash(big.NewInt(2535957)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mongoose 9
	common.HexToAddress("0xa1817B6d8D890F3943b61648992730373B71f156"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//kishu-inu 9
	common.HexToAddress("0xA2b4C0Af19cC16a6CfAcCe81F192B024d625817D"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//loopring 18
	common.HexToAddress("0xbbbbca6a901c926f240b89eacb641d8aec7aeafd"): {common.BigToHash(big.NewInt(16900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//falcon-9 9
	common.HexToAddress("0x38a94e92a19e970c144ded0b2dd47278ca11cc1f"): {common.BigToHash(big.NewInt(147)), common.BigToHash(big.NewInt(1000000000))},
	//megaweapon 9
	common.HexToAddress("0x3063c77c4ef5c1de185321ae2bc5675e17344f7f"): {common.BigToHash(big.NewInt(25500)), common.BigToHash(big.NewInt(1000000000))},
	//metafabric 18
	common.HexToAddress("0x8c6fa66c21ae3fc435790e451946a9ea82e6e523"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//allianceblock 18
	common.HexToAddress("0x00a8b738E453fFd858a7edf03bcCfe20412f0Eb0"): {common.BigToHash(big.NewInt(5453)), common.BigToHash(big.NewInt(1000000000000000000))},
	//drops 18
	common.HexToAddress("0x6bb61215298f296c55b19ad842d3df69021da2ef"): {common.BigToHash(big.NewInt(37100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rainmaker-games 18
	common.HexToAddress("0x71fc1f555a39e0b698653ab0b475488ec3c34d57"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//maker 18
	common.HexToAddress("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"): {common.BigToHash(big.NewInt(21323300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tenset 18
	common.HexToAddress("0x7FF4169a6B5122b664c51c95727d87750eC07c84"): {common.BigToHash(big.NewInt(26413)), common.BigToHash(big.NewInt(1000000000000000000))},
	//maple 18
	common.HexToAddress("0x33349b282065b0284d756f0577fb39c158f935e6"): {common.BigToHash(big.NewInt(154800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wrapped-ecomi 18
	common.HexToAddress("0x04969cd041c0cafb6ac462bd65b536a5bdb3a670"): {common.BigToHash(big.NewInt(51)), common.BigToHash(big.NewInt(1000000000000000000))},
	//audius 18
	common.HexToAddress("0x18aaa7115705e8be94bffebde57af9bfc265b998"): {common.BigToHash(big.NewInt(13827)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gm 9
	common.HexToAddress("0xbc7250c8c3eca1dfc1728620af835fca489bfdf3"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000))},
	//kiba-inu 9
	common.HexToAddress("0x4b2c54b80b77580dc02a0f6734d3bad733f50900"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//redfox-labs 18
	common.HexToAddress("0xa1d6df714f91debf4e0802a542e13067f31b8262"): {common.BigToHash(big.NewInt(746)), common.BigToHash(big.NewInt(1000000000000000000))},
	//victoria-vr 18
	common.HexToAddress("0x7d5121505149065b562c789a0145ed750e6e8cdd"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unibright 8
	common.HexToAddress("0x8400d94a5cb0fa0d041a3788e395285d61c9ee5e"): {common.BigToHash(big.NewInt(13799)), common.BigToHash(big.NewInt(100000000))},
	//keep-network 18
	common.HexToAddress("0x85eee30c52b0b379b046fb0f85f4f3dc3009afec"): {common.BigToHash(big.NewInt(6566)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polkafoundry 18
	common.HexToAddress("0x8b39b70e39aa811b69365398e0aace9bee238aeb"): {common.BigToHash(big.NewInt(10700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//eth-2x-flexible-leverage-index 18
	common.HexToAddress("0xaa6e8127831c9de45ae56bb1b0d4d4da6e5665bd"): {common.BigToHash(big.NewInt(1092295)), common.BigToHash(big.NewInt(1000000000000000000))},
	//radicle 18
	common.HexToAddress("0x31c8eacbffdd875c74b94b077895bd78cf1e64a3"): {common.BigToHash(big.NewInt(90000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//terrausd 18
	common.HexToAddress("0xa47c8bf37f92aBed4A126BDA807A7b7498661acD"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//node-squared 9
	common.HexToAddress("0x6110c64219621ce5b02fb8e8e57b54c01b83bf85"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//rubic 18
	common.HexToAddress("0xa4eed63db85311e22df4473f87ccfc3dadcfa3e3"): {common.BigToHash(big.NewInt(2198)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cerburus 9
	common.HexToAddress("0x8a14897ea5f668f36671678593fae44ae23b39fb"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//qanplatform 18
	common.HexToAddress("0xaaa7a10a8ee237ea61e8ac46c50a8db8bcc1baaa"): {common.BigToHash(big.NewInt(1036)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bully-inu 18
	common.HexToAddress("0x55d1d16fb42fce47b899010c996a3a31f6db8fd6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kylin 18
	common.HexToAddress("0x67B6D479c7bB412C54e03dCA8E1Bc6740ce6b99C"): {common.BigToHash(big.NewInt(1660)), common.BigToHash(big.NewInt(1000000000000000000))},
	//0chain 10
	common.HexToAddress("0xb9ef770b6a5e12e45983c5d80545258aa38f3b78"): {common.BigToHash(big.NewInt(3768)), common.BigToHash(big.NewInt(10000000000))},
	//radio-caca 18
	common.HexToAddress("0x12BB890508c125661E03b09EC06E404bc9289040"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polkacity 18
	common.HexToAddress("0xaA8330FB2B4D5D07ABFE7A72262752a8505C6B37"): {common.BigToHash(big.NewInt(5076)), common.BigToHash(big.NewInt(1000000000000000000))},
	//radix 18
	common.HexToAddress("0x6468e79A80C0eaB0F9A2B574c8d5bC374Af59414"): {common.BigToHash(big.NewInt(2119)), common.BigToHash(big.NewInt(1000000000000000000))},
	//all-coins-yield-capital 18
	common.HexToAddress("0xb56a1f3310578f23120182fb2e58c087efe6e147"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//clifford-inu 18
	common.HexToAddress("0x1b9baf2a3edea91ee431f02d449a1044d5726669"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mirrored-google 18
	common.HexToAddress("0x59A921Db27Dd6d4d974745B7FfC5c33932653442"): {common.BigToHash(big.NewInt(28267308)), common.BigToHash(big.NewInt(1000000000000000000))},
	//stobox-token 18
	common.HexToAddress("0x212DD60D4Bf0DA8372fe8116474602d429E5735F"): {common.BigToHash(big.NewInt(14)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polkabridge 18
	common.HexToAddress("0x298d492e8c1d909d3f63bc4a36c66c64acb3d695"): {common.BigToHash(big.NewInt(6740)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dao-maker 18
	common.HexToAddress("0x0f51bb10119727a7e5ea3538074fb341f56b09ad"): {common.BigToHash(big.NewInt(45006)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wise 18
	common.HexToAddress("0x66a0f676479cee1d7373f3dc2e2952778bff5bd6"): {common.BigToHash(big.NewInt(3654)), common.BigToHash(big.NewInt(1000000000000000000))},
	//perpetual-protocol 18
	common.HexToAddress("0xbc396689893d065f41bc2c6ecbee5e0085233447"): {common.BigToHash(big.NewInt(87373)), common.BigToHash(big.NewInt(1000000000000000000))},
	//celsius 4
	common.HexToAddress("0xaaaebe6fe48e54f431b0c390cfaf0b017d09d42d"): {common.BigToHash(big.NewInt(33400)), common.BigToHash(big.NewInt(10000))},
	//tokenlon-network-token 18
	common.HexToAddress("0x0000000000095413afc295d19edeb1ad7b71c952"): {common.BigToHash(big.NewInt(12800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polygon 18
	common.HexToAddress("0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0"): {common.BigToHash(big.NewInt(20719)), common.BigToHash(big.NewInt(1000000000000000000))},
	//k21 18
	common.HexToAddress("0xb9d99c33ea2d86ec5ec6b8a4dd816ebba64404af"): {common.BigToHash(big.NewInt(11437)), common.BigToHash(big.NewInt(1000000000000000000))},
	//civilization 18
	common.HexToAddress("0x37fe0f067fa808ffbdd12891c0858532cfe7361d"): {common.BigToHash(big.NewInt(1561)), common.BigToHash(big.NewInt(1000000000000000000))},
	//opulous 18
	common.HexToAddress("0x80d55c03180349fff4a229102f62328220a96444"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kleros 18
	common.HexToAddress("0x93ed3fbe21207ec2e8f2d3c3de6e058cb73bc04d"): {common.BigToHash(big.NewInt(1204)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ethernity-chain 18
	common.HexToAddress("0xbbc2ae13b23d715c30720f079fcd9b4a74093505"): {common.BigToHash(big.NewInt(87239)), common.BigToHash(big.NewInt(1000000000000000000))},
	//akita-inu 18
	common.HexToAddress("0x3301ee63fb29f863f2333bd4466acb46cd8323e6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//volt-inu 9
	common.HexToAddress("0x3f7aff0ef20aa2e646290dfa4e67611b2220c597"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//minds 18
	common.HexToAddress("0xb26631c6dda06ad89b93c71400d25692de89c068"): {common.BigToHash(big.NewInt(22300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//milc-platform 18
	common.HexToAddress("0x9506d37f70eB4C3d79C398d326C871aBBf10521d"): {common.BigToHash(big.NewInt(3135)), common.BigToHash(big.NewInt(1000000000000000000))},
	//alpha-brain-capital 18
	common.HexToAddress("0x5b4e9a810321e168989802474f689269ec442681"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ash 18
	common.HexToAddress("0x64d91f12ece7362f91a6f8e7940cd55f05060b92"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//glitch 18
	common.HexToAddress("0x038a68ff68c393373ec894015816e33ad41bd564"): {common.BigToHash(big.NewInt(5566)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cellframe 18
	common.HexToAddress("0x26c8afbbfe1ebaca03c2bb082e69d0476bffe099"): {common.BigToHash(big.NewInt(9281)), common.BigToHash(big.NewInt(1000000000000000000))},
	//boost-coin 18
	common.HexToAddress("0x4e0fca55a6c3a94720ded91153a27f60e26b9aa8"): {common.BigToHash(big.NewInt(89)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sidus-heroes 18
	common.HexToAddress("0x34Be5b8C30eE4fDe069DC878989686aBE9884470"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mirrored-microsoft 18
	common.HexToAddress("0x41BbEDd7286dAab5910a1f15d12CBda839852BD7"): {common.BigToHash(big.NewInt(3141157)), common.BigToHash(big.NewInt(1000000000000000000))},
	//botto 18
	common.HexToAddress("0x9dfad1b7102d46b1b197b90095b5c4e9f5845bba"): {common.BigToHash(big.NewInt(5321)), common.BigToHash(big.NewInt(1000000000000000000))},
	//revest-finance 18
	common.HexToAddress("0x120a3879da835a5af037bb2d1456bebd6b54d4ba"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mirrored-ishares-silver-trust 18
	common.HexToAddress("0x9d1555d8cB3C846Bb4f7D5B1B1080872c3166676"): {common.BigToHash(big.NewInt(215921)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lukso 18
	common.HexToAddress("0xA8b919680258d369114910511cc87595aec0be6D"): {common.BigToHash(big.NewInt(154328)), common.BigToHash(big.NewInt(1000000000000000000))},
	//waxe 8
	common.HexToAddress("0x7a2bc711e19ba6aff6ce8246c546e8c4b4944dfd"): {common.BigToHash(big.NewInt(4123800)), common.BigToHash(big.NewInt(100000000))},
	//paid-network 18
	common.HexToAddress("0x1614F18Fc94f47967A3Fbe5FfcD46d4e7Da3D787"): {common.BigToHash(big.NewInt(5648)), common.BigToHash(big.NewInt(1000000000000000000))},
	//blockchainspace 18
	common.HexToAddress("0x83e9f223e1edb3486f876ee888d76bfba26c475a"): {common.BigToHash(big.NewInt(3855)), common.BigToHash(big.NewInt(1000000000000000000))},
	//skale-network 18
	common.HexToAddress("0x00c83aecc790e8a4453e5dd3b0b4b3680501a7a7"): {common.BigToHash(big.NewInt(1757)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shiryo-inu 9
	common.HexToAddress("0x1e2f15302b90edde696593607b6bd444b64e8f02"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//doge-killer 18
	common.HexToAddress("0x27c70cd1946795b66be9d954418546998b546634"): {common.BigToHash(big.NewInt(11265929)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bondly 18
	common.HexToAddress("0x91dfbee3965baaee32784c2d546b7a0c62f268c9"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mirror-protocol 18
	common.HexToAddress("0x09a3EcAFa817268f77BE1283176B946C4ff2E608"): {common.BigToHash(big.NewInt(19394)), common.BigToHash(big.NewInt(1000000000000000000))},
	//groupdao 18
	common.HexToAddress("0x16f78145ad0b9af58747e9a97ebd99175378bd3d"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//secret-erc20 6
	common.HexToAddress("0x2b89bf8ba858cd2fcee1fada378d5cd6936968be"): {common.BigToHash(big.NewInt(67300)), common.BigToHash(big.NewInt(1000000))},
	//mirrored-alibaba 18
	common.HexToAddress("0x56aA298a19C93c6801FDde870fA63EF75Cc0aF72"): {common.BigToHash(big.NewInt(1379425)), common.BigToHash(big.NewInt(1000000000000000000))},
	//peth18c 18
	common.HexToAddress("0xA15690E9205De386Ce849889831C1668c300C1ad"): {common.BigToHash(big.NewInt(112205)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ftx-token 18
	common.HexToAddress("0x50d1c9771902476076ecfc8b2a83ad6b9355a4c9"): {common.BigToHash(big.NewInt(359799)), common.BigToHash(big.NewInt(1000000000000000000))},
	//blank-wallet 18
	common.HexToAddress("0x41a3dba3d677e573636ba691a70ff2d606c29666"): {common.BigToHash(big.NewInt(5493)), common.BigToHash(big.NewInt(1000000000000000000))},
	//keep3rv1 18
	common.HexToAddress("0x1ceb5cb57c4d4e2b2433641b95dd330a33185a44"): {common.BigToHash(big.NewInt(12142000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//singularitydao 18
	common.HexToAddress("0x993864e43caa7f7f12953ad6feb1d1ca635b875f"): {common.BigToHash(big.NewInt(12831)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gas-dao 18
	common.HexToAddress("0x6bba316c48b49bd1eac44573c5c871ff02958469"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bundles 18
	common.HexToAddress("0x8D3E855f3f55109D473735aB76F753218400fe96"): {common.BigToHash(big.NewInt(573300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//katana-inu 18
	common.HexToAddress("0x2e85ae1C47602f7927bCabc2Ff99C40aA222aE15"): {common.BigToHash(big.NewInt(37)), common.BigToHash(big.NewInt(1000000000000000000))},
	//metavice-token 18
	common.HexToAddress("0x5375fd52707ab7c8d1b088e07169fa74b0999732"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kitty-inu 9
	common.HexToAddress("0x044727e50ff30db57fad06ff4f5846eab5ea52a2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//enjinstarter 18
	common.HexToAddress("0x96610186F3ab8d73EBEe1CF950C750f3B1Fb79C2"): {common.BigToHash(big.NewInt(503)), common.BigToHash(big.NewInt(1000000000000000000))},
	//umbrella-network 18
	common.HexToAddress("0x6fc13eace26590b80cccab1ba5d51890577d83b2"): {common.BigToHash(big.NewInt(2695)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lattice-token 8
	common.HexToAddress("0xa393473d64d2F9F026B60b6Df7859A689715d092"): {common.BigToHash(big.NewInt(8270)), common.BigToHash(big.NewInt(100000000))},
	//request 18
	common.HexToAddress("0x8f8221afbb33998d8584a2b05749ba73c37a938a"): {common.BigToHash(big.NewInt(3057)), common.BigToHash(big.NewInt(1000000000000000000))},
	//zeroswap 18
	common.HexToAddress("0x2eDf094dB69d6Dcd487f1B3dB9febE2eeC0dd4c5"): {common.BigToHash(big.NewInt(1787)), common.BigToHash(big.NewInt(1000000000000000000))},
	//life-crypto 18
	common.HexToAddress("0x6c936D4AE98E6d2172dB18c16C4b601C99918EE6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ocean-protocol 18
	common.HexToAddress("0x967da4048cd07ab37855c090aaf366e4ce1b9f48"): {common.BigToHash(big.NewInt(7635)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cryptocart-v2 18
	common.HexToAddress("0x612e1726435fe38dd49a0b35b4065b56f49c8f11"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dodo 18
	common.HexToAddress("0x43dfc4159d86f3a37a5a4b3d4580b888ad7d4ddd"): {common.BigToHash(big.NewInt(8097)), common.BigToHash(big.NewInt(1000000000000000000))},
	//babydoge-coin 9
	common.HexToAddress("0xAC8E13ecC30Da7Ff04b842f21A62a1fb0f10eBd5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//digifit 9
	common.HexToAddress("0xa420dd089a33d3751e8750f0b3554c72761dc83e"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//jacywaya 9
	common.HexToAddress("0x08f2991a6eff2671cf791b82aeae64fbbfdd0633"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//stratos 18
	common.HexToAddress("0x08c32b0726C5684024ea6e141C50aDe9690bBdcc"): {common.BigToHash(big.NewInt(20000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gysr 18
	common.HexToAddress("0xbea98c05eeae2f3bc8c3565db7551eb738c8ccab"): {common.BigToHash(big.NewInt(2723)), common.BigToHash(big.NewInt(1000000000000000000))},
	//metaverse-index 18
	common.HexToAddress("0x72e364f2abdc788b7e918bc238b21f109cd634d7"): {common.BigToHash(big.NewInt(1886533)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kleekai 9
	common.HexToAddress("0x382f0160c24f5c515a19f155bac14d479433a407"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//stake-dao 18
	common.HexToAddress("0x73968b9a57c6e53d41345fd57a6e6ae27d6cdb2f"): {common.BigToHash(big.NewInt(18800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//storj 8
	common.HexToAddress("0xb64ef51c888972c908cfacf59b47c1afbc0ab8ac"): {common.BigToHash(big.NewInt(15800)), common.BigToHash(big.NewInt(100000000))},
	//public-mint 18
	common.HexToAddress("0x0CDF9acd87E940837ff21BB40c9fd55F68bba059"): {common.BigToHash(big.NewInt(1512)), common.BigToHash(big.NewInt(1000000000000000000))},
	//baby-doge-coin 9
	common.HexToAddress("0xAC57De9C1A09FeC648E93EB98875B212DB0d460B"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//inuyasha 18
	common.HexToAddress("0x5bddbfdc228e1bbdb9ef5ca1dc56b54c4d6d6621"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//holo 18
	common.HexToAddress("0x6c6ee5e31d828de241282b9606c8e98ea48526e2"): {common.BigToHash(big.NewInt(64)), common.BigToHash(big.NewInt(1000000000000000000))},
	//syntropy 18
	common.HexToAddress("0xa8c8CfB141A3bB59FEA1E2ea6B79b5ECBCD7b6ca"): {common.BigToHash(big.NewInt(2624)), common.BigToHash(big.NewInt(1000000000000000000))},
	//verox 18
	common.HexToAddress("0x87DE305311D5788e8da38D19bb427645b09CB4e5"): {common.BigToHash(big.NewInt(1625677)), common.BigToHash(big.NewInt(1000000000000000000))},
	//decentr 18
	common.HexToAddress("0x30f271c9e86d2b7d00a6376cd96a1cfbd5f0b9b3"): {common.BigToHash(big.NewInt(614)), common.BigToHash(big.NewInt(1000000000000000000))},
	//oraichain-token 18
	common.HexToAddress("0x4c11249814f11b9346808179cf06e71ac328c1b5"): {common.BigToHash(big.NewInt(71500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//harvest-finance 18
	common.HexToAddress("0xa0246c9032bC3A600820415aE600c6388619A14D"): {common.BigToHash(big.NewInt(1544733)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kirobo 18
	common.HexToAddress("0xb1191f691a355b43542bea9b8847bc73e7abb137"): {common.BigToHash(big.NewInt(3894)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mask-network 18
	common.HexToAddress("0x69af81e73a73b40adf4f3d4223cd9b1ece623074"): {common.BigToHash(big.NewInt(102100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//thorchain-erc20 18
	common.HexToAddress("0x3155ba85d5f96b2d030a4966af206230e46849cb"): {common.BigToHash(big.NewInt(66399)), common.BigToHash(big.NewInt(1000000000000000000))},
	//flux-dao 18
	common.HexToAddress("0x3ea8ea4237344c9931214796d9417af1a1180770"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//floki-musk 18
	common.HexToAddress("0x67cc621ab2d086a101cff3340df0a065ac75827c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//saffron-finance 18
	common.HexToAddress("0xb753428af26e81097e7fd17f40c88aaa3e04902c"): {common.BigToHash(big.NewInt(2568900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mahadao 18
	common.HexToAddress("0xb4d930279552397bba2ee473229f89ec245bc365"): {common.BigToHash(big.NewInt(56000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xy-finance 18
	common.HexToAddress("0x77777777772cf0455fB38eE0e75f38034dFa50DE"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//signata 18
	common.HexToAddress("0x3ebb4A4e91Ad83BE51F8d596533818b246F4bEe1"): {common.BigToHash(big.NewInt(5666)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fantasy-world-gold 9
	common.HexToAddress("0x7345Ffe6291bc15381A4110831013e8fe9f93253"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//deficliq 18
	common.HexToAddress("0x0Def8d8addE14c9eF7c2a986dF3eA4Bd65826767"): {common.BigToHash(big.NewInt(225)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mirrored-amazon 18
	common.HexToAddress("0x0cae9e4d663793c2a2A0b211c1Cf4bBca2B9cAa7"): {common.BigToHash(big.NewInt(33093092)), common.BigToHash(big.NewInt(1000000000000000000))},
	//niifi 15
	common.HexToAddress("0x852e5427c86a3b46dd25e5fe027bb15f53c4bcb8"): {common.BigToHash(big.NewInt(350)), common.BigToHash(big.NewInt(1000000000000000))},
	//polkafantasy 18
	common.HexToAddress("0x948c70Dc6169Bfb10028FdBE96cbC72E9562b2Ac"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kuma-inu 18
	common.HexToAddress("0x48c276e8d03813224bb1e55f953adb6d02fd3e02"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//parsiq 18
	common.HexToAddress("0x362bc847A3a9637d3af6624EeC853618a43ed7D2"): {common.BigToHash(big.NewInt(3912)), common.BigToHash(big.NewInt(1000000000000000000))},
	//reserve-rights 18
	common.HexToAddress("0x8762db106b2c2a0bccb3a80d1ed41273552616e8"): {common.BigToHash(big.NewInt(257)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bidao 18
	common.HexToAddress("0x25e1474170c4c0aA64fa98123bdc8dB49D7802fa"): {common.BigToHash(big.NewInt(121)), common.BigToHash(big.NewInt(1000000000000000000))},
	//naos-finance 18
	common.HexToAddress("0x4a615bb7166210cce20e6642a6f8fb5d4d044496"): {common.BigToHash(big.NewInt(3558)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cocktail-bar 8
	common.HexToAddress("0x22b6c31c2beb8f2d0d5373146eed41ab9ede3caf"): {common.BigToHash(big.NewInt(2218438)), common.BigToHash(big.NewInt(100000000))},
	//render-token 18
	common.HexToAddress("0x6de037ef9ad2725eb40118bb1702ebb27e4aeb24"): {common.BigToHash(big.NewInt(37300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fnk-wallet 18
	common.HexToAddress("0xb5fe099475d3030dde498c3bb6f3854f762a48ad"): {common.BigToHash(big.NewInt(301)), common.BigToHash(big.NewInt(1000000000000000000))},
	//b-protocol 18
	common.HexToAddress("0xbbbbbbb5aa847a2003fbc6b5c16df0bd1e725f61"): {common.BigToHash(big.NewInt(70500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//whale 4
	common.HexToAddress("0x9355372396e3F6daF13359B7b607a3374cc638e0"): {common.BigToHash(big.NewInt(119000)), common.BigToHash(big.NewInt(10000))},
	//bao-finance 18
	common.HexToAddress("0x374cb8c27130e2c9e04f44303f3c8351b9de61c1"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pickle-finance 18
	common.HexToAddress("0x429881672B9AE42b8EbA0E26cD9C73711b891Ca5"): {common.BigToHash(big.NewInt(87219)), common.BigToHash(big.NewInt(1000000000000000000))},
	//algovest 18
	common.HexToAddress("0x94d916873b22c9c1b53695f1c002f78537b9b3b2"): {common.BigToHash(big.NewInt(15612)), common.BigToHash(big.NewInt(1000000000000000000))},
	//multi-farm-capital 9
	common.HexToAddress("0xb77b6fe3e33ce2a15bae846658fca5da62ab8ac0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//dopex-rdpx 18
	common.HexToAddress("0x0ff5a8451a839f5f0bb3562689d9a44089738d11"): {common.BigToHash(big.NewInt(1241000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chain-guardians 18
	common.HexToAddress("0x1fe24f25b1cf609b9c4e7e12d802e3640dfa5e43"): {common.BigToHash(big.NewInt(6887)), common.BigToHash(big.NewInt(1000000000000000000))},
	//geeq 18
	common.HexToAddress("0x6b9f031d718dded0d681c20cb754f97b3bb81b78"): {common.BigToHash(big.NewInt(10310)), common.BigToHash(big.NewInt(1000000000000000000))},
	//insurace 18
	common.HexToAddress("0x544c42fbb96b39b21df61cf322b5edc285ee7429"): {common.BigToHash(big.NewInt(10400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mirrored-tesla 18
	common.HexToAddress("0x21cA39943E91d704678F5D00b6616650F066fD63"): {common.BigToHash(big.NewInt(10641913)), common.BigToHash(big.NewInt(1000000000000000000))},
	//golem-network-tokens 18
	common.HexToAddress("0x7DD9c5Cba05E151C895FDe1CF355C9A1D5DA6429"): {common.BigToHash(big.NewInt(4205)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gemini-dollar 2
	common.HexToAddress("0x056Fd409E1d7A124BD7017459dFEa2F387b6d5Cd"): {common.BigToHash(big.NewInt(10100)), common.BigToHash(big.NewInt(100))},
	//synthetix-network-token 18
	common.HexToAddress("0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f"): {common.BigToHash(big.NewInt(55199)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cvault-finance 18
	common.HexToAddress("0x62359ed7505efc61ff1d56fef82158ccaffa23d7"): {common.BigToHash(big.NewInt(68849096)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wagyuswap 18
	common.HexToAddress("0x7FA7dF4996AC59F398476892cfB195eD38543520"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gencoin-capital 9
	common.HexToAddress("0x0b569fa433faa7f01f3ea880193de38044b41de0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//capital-aggregator-token 9
	common.HexToAddress("0x3734dc0d241b5ad886fa6bff45ffa67252ac0e89"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//trade-race-manager 6
	common.HexToAddress("0x8b3870df408ff4d7c3a26df852d41034eda11d81"): {common.BigToHash(big.NewInt(17100)), common.BigToHash(big.NewInt(1000000))},
	//sora 18
	common.HexToAddress("0x40FD72257597aA14C7231A7B1aaa29Fce868F677"): {common.BigToHash(big.NewInt(987211)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pbtc35a 18
	common.HexToAddress("0xA8b12Cc90AbF65191532a12bb5394A714A46d358"): {common.BigToHash(big.NewInt(885513)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sarcophagus 18
	common.HexToAddress("0x7697b462a7c4ff5f8b55bdbc2f4076c2af9cf51a"): {common.BigToHash(big.NewInt(9593)), common.BigToHash(big.NewInt(1000000000000000000))},
	//coldstack 18
	common.HexToAddress("0x675bbc7514013e2073db7a919f6e4cbef576de37"): {common.BigToHash(big.NewInt(15580)), common.BigToHash(big.NewInt(1000000000000000000))},
	//infinitygaming 9
	common.HexToAddress("0x95b4e47025372ded4b73f9b5f0671b94a81445bc"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//chrono-tech 8
	common.HexToAddress("0x485d17A6f1B8780392d53D64751824253011A260"): {common.BigToHash(big.NewInt(2416923)), common.BigToHash(big.NewInt(100000000))},
	//stackos 18
	common.HexToAddress("0x56a86d648c435dc707c8405b78e2ae8eb4e60ba4"): {common.BigToHash(big.NewInt(762)), common.BigToHash(big.NewInt(1000000000000000000))},
	//origintrail 18
	common.HexToAddress("0xaa7a9ca87d3694b5755f213b5d04094b8d0f0a6f"): {common.BigToHash(big.NewInt(10200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nix-bridge-token 18
	common.HexToAddress("0x2e2364966267B5D7D2cE6CD9A9B5bD19d9C7C6A9"): {common.BigToHash(big.NewInt(3182700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rangers-protocol 18
	common.HexToAddress("0x0E5C8C387C5EBa2eCbc137aD012aeD5Fe729e251"): {common.BigToHash(big.NewInt(164981)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bonded-finance 8
	common.HexToAddress("0x5dc02ea99285e17656b8350722694c35154db1e8"): {common.BigToHash(big.NewInt(191)), common.BigToHash(big.NewInt(100000000))},
	//naga 18
	common.HexToAddress("0x72dd4b6bd852a3aa172be4d6c5a6dbec588cf131"): {common.BigToHash(big.NewInt(9289)), common.BigToHash(big.NewInt(1000000000000000000))},
	//exotix 9
	common.HexToAddress("0x230bf0637628ef356b63d389e2ec6c77c8853a11"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//antimatter 18
	common.HexToAddress("0x9B99CcA871Be05119B2012fd4474731dd653FEBe"): {common.BigToHash(big.NewInt(5050)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ryoshis-vision 18
	common.HexToAddress("0x777E2ae845272a2F540ebf6a3D03734A5a8f618e"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//zigcoin 18
	common.HexToAddress("0xb2617246d0c6c0087f18703d576831899ca94f01"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//singularitynet 8
	common.HexToAddress("0x5B7533812759B45C2B44C19e320ba2cD2681b542"): {common.BigToHash(big.NewInt(1748)), common.BigToHash(big.NewInt(100000000))},
	//pop 18
	common.HexToAddress("0x7fC3eC3574d408F3b59CD88709baCb42575EBF2b"): {common.BigToHash(big.NewInt(1019)), common.BigToHash(big.NewInt(1000000000000000000))},
	//uncx 18
	common.HexToAddress("0xaDB2437e6F65682B85F814fBc12FeC0508A7B1D0"): {common.BigToHash(big.NewInt(5192700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lossless 18
	common.HexToAddress("0x3b9be07d622accaed78f479bc0edabfd6397e320"): {common.BigToHash(big.NewInt(7927)), common.BigToHash(big.NewInt(1000000000000000000))},
	//madworld 8
	common.HexToAddress("0x31c2415c946928e9FD1Af83cdFA38d3eDBD4326f"): {common.BigToHash(big.NewInt(1396)), common.BigToHash(big.NewInt(100000000))},
	//xfai 18
	common.HexToAddress("0x4aa41bC1649C9C3177eD16CaaA11482295fC7441"): {common.BigToHash(big.NewInt(687)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pooltogether 18
	common.HexToAddress("0x0cec1a9154ff802e7934fc916ed7ca50bde6844e"): {common.BigToHash(big.NewInt(43500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pawtocol 18
	common.HexToAddress("0x70d2b7c19352bb76e4409858ff5746e500f2b67c"): {common.BigToHash(big.NewInt(610)), common.BigToHash(big.NewInt(1000000000000000000))},
	//api3 18
	common.HexToAddress("0x0b38210ea11411557c13457D4dA7dC6ea731B88a"): {common.BigToHash(big.NewInt(38000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bone 18
	common.HexToAddress("0x5C84bc60a796534bfeC3439Af0E6dB616A966335"): {common.BigToHash(big.NewInt(131)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mirrored-united-states-oil-fund 18
	common.HexToAddress("0x31c63146a635EB7465e5853020b39713AC356991"): {common.BigToHash(big.NewInt(583736)), common.BigToHash(big.NewInt(1000000000000000000))},
	//apy-finance 18
	common.HexToAddress("0x95a4492F028aa1fd432Ea71146b433E7B4446611"): {common.BigToHash(big.NewInt(2264)), common.BigToHash(big.NewInt(1000000000000000000))},
	//digitalbits 7
	common.HexToAddress("0xb9eefc4b0d472a44be93970254df4f4016569d27"): {common.BigToHash(big.NewInt(3972)), common.BigToHash(big.NewInt(10000000))},
	//yop 8
	common.HexToAddress("0xae1eaae3f627aaca434127644371b67b18444051"): {common.BigToHash(big.NewInt(2695)), common.BigToHash(big.NewInt(100000000))},
	//numbers-protocol 18
	common.HexToAddress("0x3496b523e5c00a4b4150d6721320cddb234c3079"): {common.BigToHash(big.NewInt(8767)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mononoke-inu 9
	common.HexToAddress("0x4da08a1bff50be96bded5c7019227164b49c2bfc"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//occamfi 18
	common.HexToAddress("0x2f109021afe75b949429fe30523ee7c0d5b27207"): {common.BigToHash(big.NewInt(23000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sienna-erc20 18
	common.HexToAddress("0x9b00e6E8D787b13756eb919786c9745054DB64f9"): {common.BigToHash(big.NewInt(111115)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bridge-mutual 18
	common.HexToAddress("0x725c263e32c72ddc3a19bea12c5a0479a81ee688"): {common.BigToHash(big.NewInt(2176)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sentivate 18
	common.HexToAddress("0x7865af71cf0b288b4e7f654f4f7851eb46a2b7f8"): {common.BigToHash(big.NewInt(151)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rentible 18
	common.HexToAddress("0x2a039b1d9bbdccbb91be28691b730ca893e5e743"): {common.BigToHash(big.NewInt(10971)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tokenplace 8
	common.HexToAddress("0x4fb721ef3bf99e0f2c193847afa296b9257d3c30"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100000000))},
	//paribus 18
	common.HexToAddress("0xd528cf2e081f72908e086f8800977df826b5a483"): {common.BigToHash(big.NewInt(191)), common.BigToHash(big.NewInt(1000000000000000000))},
	//captain-inu 18
	common.HexToAddress("0x7cca2e1c9b0519f52029467914a15e782bf66971"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ridotto 18
	common.HexToAddress("0x4740735aa98dc8aa232bd049f8f0210458e7fca3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//everrise 18
	common.HexToAddress("0x0cd022dde27169b20895e0e2b2b8a33b25e63579"): {common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(1000000000000000000))},
	//b-cube-ai 18
	common.HexToAddress("0x93C9175E26F57d2888c7Df8B470C9eeA5C0b0A93"): {common.BigToHash(big.NewInt(1874)), common.BigToHash(big.NewInt(1000000000000000000))},
	//alkimi 18
	common.HexToAddress("0x3106a0a076BeDAE847652F42ef07FD58589E001f"): {common.BigToHash(big.NewInt(3183)), common.BigToHash(big.NewInt(1000000000000000000))},
	//orion-protocol 8
	common.HexToAddress("0x0258F474786DdFd37ABCE6df6BBb1Dd5dfC4434a"): {common.BigToHash(big.NewInt(50626)), common.BigToHash(big.NewInt(100000000))},
	//pnetwork 18
	common.HexToAddress("0x89ab32156e46f46d02ade3fecbe5fc4243b9aaed"): {common.BigToHash(big.NewInt(8474)), common.BigToHash(big.NewInt(1000000000000000000))},
	//infinity-token 9
	common.HexToAddress("0x7fe4fbad1fee10d6cf8e08198608209a9275944c"): {common.BigToHash(big.NewInt(10)), common.BigToHash(big.NewInt(1000000000))},
	//covercompared 18
	common.HexToAddress("0x3c03b4ec9477809072ff9cc9292c9b25d4a8e6c6"): {common.BigToHash(big.NewInt(863)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lobby 9
	common.HexToAddress("0xac042d9284df95cc6bd35982f6a61e3e7a6f875b"): {common.BigToHash(big.NewInt(26)), common.BigToHash(big.NewInt(1000000000))},
	//kattana 18
	common.HexToAddress("0x491e136ff7ff03e6ab097e54734697bb5802fc1c"): {common.BigToHash(big.NewInt(60092)), common.BigToHash(big.NewInt(1000000000000000000))},
	//meter-governance-mapped-by-meter-io 18
	common.HexToAddress("0xBd2949F67DcdC549c6Ebe98696449Fa79D988A9F"): {common.BigToHash(big.NewInt(48013)), common.BigToHash(big.NewInt(1000000000000000000))},
	//everipedia 18
	common.HexToAddress("0x579cea1889991f68acc35ff5c3dd0621ff29b0c9"): {common.BigToHash(big.NewInt(114)), common.BigToHash(big.NewInt(1000000000000000000))},
	//akropolis 18
	common.HexToAddress("0x8ab7404063ec4dbcfd4598215992dc3f8ec853d7"): {common.BigToHash(big.NewInt(202)), common.BigToHash(big.NewInt(1000000000000000000))},
	//monstaverse 9
	common.HexToAddress("0xba75fbc4c7a553081f7a137b6e652520db444660"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//mirrored-invesco-qqq-trust 18
	common.HexToAddress("0x13B02c8dE71680e71F0820c996E4bE43c2F57d15"): {common.BigToHash(big.NewInt(3835037)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gold-fever 18
	common.HexToAddress("0x2653891204f463fb2a2f4f412564b19e955166ae"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ramp 18
	common.HexToAddress("0x33D0568941C0C64ff7e0FB4fbA0B11BD37deEd9f"): {common.BigToHash(big.NewInt(1641)), common.BigToHash(big.NewInt(1000000000000000000))},
	//alpha 18
	common.HexToAddress("0x138c2f1123cf3f82e4596d097c118eac6684940b"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//guzzler 18
	common.HexToAddress("0x9f4909cc95fb870bf48c128c1fdbb5f482797632"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bloxmove 18
	common.HexToAddress("0x38d9eb07a7b8df7d86f440a4a5c4a4c1a27e1a08"): {common.BigToHash(big.NewInt(28600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//meta 18
	common.HexToAddress("0xa3BeD4E1c75D00fa6f4E5E6922DB7261B5E9AcD2"): {common.BigToHash(big.NewInt(6772)), common.BigToHash(big.NewInt(1000000000000000000))},
	//vidya 18
	common.HexToAddress("0x3d3d35bb9bec23b06ca00fe472b50e7a4c692c30"): {common.BigToHash(big.NewInt(2519)), common.BigToHash(big.NewInt(1000000000000000000))},
	//card-starter 18
	common.HexToAddress("0x3d6f0dea3ac3c607b3998e6ce14b6350721752d9"): {common.BigToHash(big.NewInt(46800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//swingby 18
	common.HexToAddress("0x8287c7b963b405b7b8d467db9d79eec40625b13a"): {common.BigToHash(big.NewInt(269)), common.BigToHash(big.NewInt(1000000000000000000))},
	//marlin 18
	common.HexToAddress("0x57b946008913b82e4df85f501cbaed910e58d26c"): {common.BigToHash(big.NewInt(545)), common.BigToHash(big.NewInt(1000000000000000000))},
	//don-key 18
	common.HexToAddress("0x217ddead61a42369a266f1fb754eb5d3ebadc88a"): {common.BigToHash(big.NewInt(3030)), common.BigToHash(big.NewInt(1000000000000000000))},
	//swapdex 7
	common.HexToAddress("0x041fdd6637ecfd96af8804278ac12660ac2d12c0"): {common.BigToHash(big.NewInt(453)), common.BigToHash(big.NewInt(10000000))},
	//kori-inu 9
	common.HexToAddress("0x345dadb10a200f10814ad8523fca0f2d958c3370"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//futureswap 18
	common.HexToAddress("0x0e192d382a36de7011f795acc4391cd302003606"): {common.BigToHash(big.NewInt(36097)), common.BigToHash(big.NewInt(1000000000000000000))},
	//union-protocol-governance-token 18
	common.HexToAddress("0x226f7b842e0f0120b7e194d05432b3fd14773a9d"): {common.BigToHash(big.NewInt(39)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bistroo 18
	common.HexToAddress("0x6e8908cfa881c9f6f2c64d3436e7b80b1bf0093f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//doont-buy 9
	common.HexToAddress("0x4ece5c5cfb9b960a49aae739e15cdb6cfdcc5782"): {common.BigToHash(big.NewInt(140)), common.BigToHash(big.NewInt(1000000000))},
	//sphynx-eth 18
	common.HexToAddress("0x94dfd4e2210fa5b752c3cd0f381edad9da6640f8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//domi-online 18
	common.HexToAddress("0x45C2F8c9B4c0bDC76200448cc26C48ab6ffef83F"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//deepspace-token 18
	common.HexToAddress("0x528b3e98c63ce21c6f680b713918e0f89dfae555"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ethpad 18
	common.HexToAddress("0x8dB1D28Ee0d822367aF8d220C0dc7cB6fe9DC442"): {common.BigToHash(big.NewInt(746)), common.BigToHash(big.NewInt(1000000000000000000))},
	//finxflo 18
	common.HexToAddress("0x8a40c222996f9f3431f63bf80244c36822060f12"): {common.BigToHash(big.NewInt(1524)), common.BigToHash(big.NewInt(1000000000000000000))},
	//monavale 18
	common.HexToAddress("0x275f5Ad03be0Fa221B4C6649B8AeE09a42D9412A"): {common.BigToHash(big.NewInt(5211933)), common.BigToHash(big.NewInt(1000000000000000000))},
	//c20 18
	common.HexToAddress("0x26e75307fc0c021472feb8f727839531f112f317"): {common.BigToHash(big.NewInt(39200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//aleph-im 18
	common.HexToAddress("0x27702a26126e0b3702af63ee09ac4d1a084ef628"): {common.BigToHash(big.NewInt(5086)), common.BigToHash(big.NewInt(1000000000000000000))},
	//oiler-network 18
	common.HexToAddress("0x0275e1001e293c46cfe158b3702aade0b99f88a5"): {common.BigToHash(big.NewInt(5123)), common.BigToHash(big.NewInt(1000000000000000000))},
	//orion-money 18
	common.HexToAddress("0x727f064a78dc734d33eec18d5370aef32ffd46e4"): {common.BigToHash(big.NewInt(4652)), common.BigToHash(big.NewInt(1000000000000000000))},
	//global-coin-research 4
	common.HexToAddress("0x6307b25a665efc992ec1c1bc403c38f3ddd7c661"): {common.BigToHash(big.NewInt(21300)), common.BigToHash(big.NewInt(10000))},
	//unilend 18
	common.HexToAddress("0x0202Be363B8a4820f3F4DE7FaF5224fF05943AB1"): {common.BigToHash(big.NewInt(5696)), common.BigToHash(big.NewInt(1000000000000000000))},
	//complifi 18
	common.HexToAddress("0x752efadc0a7e05ad1bcccda22c141d01a75ef1e4"): {common.BigToHash(big.NewInt(17282)), common.BigToHash(big.NewInt(1000000000000000000))},
	//realm 18
	common.HexToAddress("0x464fdb8affc9bac185a7393fd4298137866dcfb8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//robo-inu-finance 9
	common.HexToAddress("0x7b32e70e8d73ac87c1b342e063528b2930b15ceb"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//cino-games 18
	common.HexToAddress("0x7A2C7928c8CF294E25cA7db8a379278c5b0cFa0F"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xdai 18
	common.HexToAddress("0x0Ae055097C6d159879521C384F1D2123D1f195e6"): {common.BigToHash(big.NewInt(152900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nftrade 18
	common.HexToAddress("0x8e0fe2947752be0d5acf73aae77362daf79cb379"): {common.BigToHash(big.NewInt(7477)), common.BigToHash(big.NewInt(1000000000000000000))},
	//jigstack 18
	common.HexToAddress("0x1f8a626883d7724dbd59ef51cbd4bf1cf2016d13"): {common.BigToHash(big.NewInt(56)), common.BigToHash(big.NewInt(1000000000000000000))},
	//opendao 18
	common.HexToAddress("0x3b484b82567a09e2588a13d54d032153f0c0aee0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dinger-token 9
	common.HexToAddress("0x9e5bd9d9fad182ff0a93ba8085b664bcab00fa68"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//ren 18
	common.HexToAddress("0x408e41876cccdc0f92210600ef50372656052a38"): {common.BigToHash(big.NewInt(4773)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tidal-finance 18
	common.HexToAddress("0x29cbd0510eec0327992cd6006e63f9fa8e7f33b7"): {common.BigToHash(big.NewInt(23)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pinknode 18
	common.HexToAddress("0xAF691508BA57d416f895e32a1616dA1024e882D2"): {common.BigToHash(big.NewInt(1082)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gamestarter 5
	common.HexToAddress("0xD567B5F02b9073aD3a982a099a23Bf019FF11d1c"): {common.BigToHash(big.NewInt(15700)), common.BigToHash(big.NewInt(100000))},
	//yieldly 18
	common.HexToAddress("0x88cb253d4c8cab8cdf7948a9251db85a13669e23"): {common.BigToHash(big.NewInt(179)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cujo-inu 9
	common.HexToAddress("0x612c393dace91284dafc23e623aab084fa0ffa64"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//dia 18
	common.HexToAddress("0x84ca8bc7997272c7cfb4d0cd3d55cd942b3c9419"): {common.BigToHash(big.NewInt(11299)), common.BigToHash(big.NewInt(1000000000000000000))},
	//powerpool 18
	common.HexToAddress("0x38e4adb44ef08f22f5b5b76a8f0c2d0dcbe7dca1"): {common.BigToHash(big.NewInt(12922)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mantra-dao 18
	common.HexToAddress("0x3593d125a4f7849a1b059e64f4517a86dd60c95d"): {common.BigToHash(big.NewInt(1317)), common.BigToHash(big.NewInt(1000000000000000000))},
	//abyss 18
	common.HexToAddress("0x0e8d6b471e332f140e7d9dbb99e5e3822f728da6"): {common.BigToHash(big.NewInt(622)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mimir-token 18
	common.HexToAddress("0x71dc40668682a124231301414167e4cf7f55383c"): {common.BigToHash(big.NewInt(2270)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tether 6
	common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000))},
	//cia-protocol 9
	common.HexToAddress("0x52f4d5ee6c91e01be67ca1f64b11ed0ee370817d"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//coinweb 18
	common.HexToAddress("0x505b5eda5e25a67e1c24a2bf1a527ed9eb88bf04"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ampnet-asset-platform-and-exchange 18
	common.HexToAddress("0xbfd815347d024f449886c171f78fa5b8e6790811"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fear-nfts 18
	common.HexToAddress("0x88a9a52f944315d5b4e917b9689e65445c401e83"): {common.BigToHash(big.NewInt(11000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//velas 18
	common.HexToAddress("0x8c543aed163909142695f2d2acd0d55791a9edb9"): {common.BigToHash(big.NewInt(3769)), common.BigToHash(big.NewInt(1000000000000000000))},
	//virtue-poker 18
	common.HexToAddress("0x5eeaa2dcb23056f4e8654a349e57ebe5e76b5e6e"): {common.BigToHash(big.NewInt(1114)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shopping 18
	common.HexToAddress("0x9b02dd390a603add5c07f9fd9175b7dabe8d63b7"): {common.BigToHash(big.NewInt(174500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//velaspad 18
	common.HexToAddress("0xb8e3bB633F7276cc17735D86154E0ad5ec9928C0"): {common.BigToHash(big.NewInt(4803)), common.BigToHash(big.NewInt(1000000000000000000))},
	//uniqly 18
	common.HexToAddress("0x3758e00b100876c854636ef8db61988931bb8025"): {common.BigToHash(big.NewInt(8572)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pathdao 18
	common.HexToAddress("0x2a2550e0a75acec6d811ae3930732f7f3ad67588"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hellsing-inu 9
	common.HexToAddress("0xb087c2180e3134db396977065817aed91fea6ead"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//rio-defi 18
	common.HexToAddress("0xaf9f549774ecedbd0966c52f250acc548d3f36e5"): {common.BigToHash(big.NewInt(403)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ternoa 18
	common.HexToAddress("0x03be5c903c727ee2c8c4e9bc0acc860cca4715e2"): {common.BigToHash(big.NewInt(858)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nyx-token 9
	common.HexToAddress("0x118b552725e1892137740cB4d29390D952709639"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//unlock-protocol 18
	common.HexToAddress("0x90de74265a416e1393a450752175aed98fe11517"): {common.BigToHash(big.NewInt(963800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//armor 18
	common.HexToAddress("0x1337def16f9b486faed0293eb623dc8395dfe46a"): {common.BigToHash(big.NewInt(531)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shyft-network 18
	common.HexToAddress("0xb17C88bDA07D28B3838E0c1dE6a30eAfBCF52D85"): {common.BigToHash(big.NewInt(4943)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dose 18
	common.HexToAddress("0xb31ef9e52d94d4120eb44fe1ddfde5b4654a6515"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//goat-token 9
	common.HexToAddress("0x74edaf28fc4b9e6a1618d613839daaf6a9d075db"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//freeway-token 18
	common.HexToAddress("0xf151980e7a781481709e8195744bf2399fb3cba4"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gamercoin 18
	common.HexToAddress("0x728f30fa2f100742c7949d1961804fa8e0b1387d"): {common.BigToHash(big.NewInt(617)), common.BigToHash(big.NewInt(1000000000000000000))},
	//prosper 18
	common.HexToAddress("0x8642A849D0dcb7a15a974794668ADcfbe4794B56"): {common.BigToHash(big.NewInt(10400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//oin-finance 8
	common.HexToAddress("0x9aeB50f542050172359A0e1a25a9933Bc8c01259"): {common.BigToHash(big.NewInt(1953)), common.BigToHash(big.NewInt(100000000))},
	//aag-ventures 18
	common.HexToAddress("0x5ba19d656b65f1684cfea4af428c23b9f3628f97"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//88mph 18
	common.HexToAddress("0x8888801af4d980682e47f1a9036e589479e835c5"): {common.BigToHash(big.NewInt(324632)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gerowallet 18
	common.HexToAddress("0x3431f91b3a388115f00c5ba9fdb899851d005fb5"): {common.BigToHash(big.NewInt(549)), common.BigToHash(big.NewInt(1000000000000000000))},
	//saint-inu 9
	common.HexToAddress("0x6fc5af63990aa9e5c5543f5cd8ed148bfa6d9d19"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//zero-tech 18
	common.HexToAddress("0x0eC78ED49C2D27b315D462d43B5BAB94d2C79bf8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kollect 18
	common.HexToAddress("0x1CC30e2EAc975416060Ec6FE682041408420d414"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hxro 18
	common.HexToAddress("0x4bd70556ae3f8a6ec6c4080a0c327b24325438f3"): {common.BigToHash(big.NewInt(4636)), common.BigToHash(big.NewInt(1000000000000000000))},
	//crustnetwork 18
	common.HexToAddress("0x32a7C02e79c4ea1008dD6564b35F131428673c41"): {common.BigToHash(big.NewInt(117825)), common.BigToHash(big.NewInt(1000000000000000000))},
	//basic-attention-token 18
	common.HexToAddress("0x0d8775f648430679a709e98d2b0cb6250d2887ef"): {common.BigToHash(big.NewInt(10900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cream-finance 18
	common.HexToAddress("0x2ba592f78db6436527729929aaf6c908497cb200"): {common.BigToHash(big.NewInt(417539)), common.BigToHash(big.NewInt(1000000000000000000))},
	//graphlinq-protocol 18
	common.HexToAddress("0x9f9c8ec3534c3ce16f928381372bfbfbfb9f4d24"): {common.BigToHash(big.NewInt(197)), common.BigToHash(big.NewInt(1000000000000000000))},
	//filecoin-standard-hashrate-token 18
	common.HexToAddress("0x7346ad4c8cd1886ff6d16072bcea5dfc0bc24ca2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//energy-web-token 18
	common.HexToAddress("0x178c820f862b14f316509ec36b13123da19a6054"): {common.BigToHash(big.NewInt(82410)), common.BigToHash(big.NewInt(1000000000000000000))},
	//epik-prime 18
	common.HexToAddress("0x4da0c48376c277cdbd7fc6fdc6936dee3e4adf75"): {common.BigToHash(big.NewInt(1721)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shiba-girlfriend 18
	common.HexToAddress("0x505a84a03e382331a1be487b632cf357748b65d6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gro-dao-token 18
	common.HexToAddress("0x3Ec8798B81485A254928B70CDA1cf0A2BB0B74D7"): {common.BigToHash(big.NewInt(35800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pulsepad 18
	common.HexToAddress("0x8a74bc8c372bc7f0e9ca3f6ac0df51be15aec47a"): {common.BigToHash(big.NewInt(1222)), common.BigToHash(big.NewInt(1000000000000000000))},
	//aladdindao 18
	common.HexToAddress("0xb26C4B3Ca601136Daf98593feAeff9E0CA702a8D"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ok-lets-go 9
	common.HexToAddress("0x5dbb9f64cd96e2dbbca58d14863d615b67b42f2e"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//talaria-inu 18
	common.HexToAddress("0x6765fdd028be3d7874bc2bb3d7d5ca01c1bf14b2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fren-token 9
	common.HexToAddress("0x37941b3fdb2bd332e667d452a58be01bcacb923e"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//dforce 18
	common.HexToAddress("0x431ad2ff6a9c365805ebad47ee021148d6f7dbe0"): {common.BigToHash(big.NewInt(1158)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xfund 9
	common.HexToAddress("0x892a6f9df0147e5f079b0993f486f9aca3c87881"): {common.BigToHash(big.NewInt(9078500)), common.BigToHash(big.NewInt(1000000000))},
	//brokoli-network 18
	common.HexToAddress("0x4674a4F24C5f63D53F22490Fb3A08eAAAD739ff8"): {common.BigToHash(big.NewInt(4913)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shinchan-token 9
	common.HexToAddress("0xbaa9af8a83500ac4137c555b9e58ccb3e1f2269d"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//swissborg 8
	common.HexToAddress("0xba9d4199fab4f26efe3551d490e3821486f135ba"): {common.BigToHash(big.NewInt(5638)), common.BigToHash(big.NewInt(100000000))},
	//mobi-finance 18
	common.HexToAddress("0xb2dbf14d0b47ed3ba02bdb7c954e05a72deb7544"): {common.BigToHash(big.NewInt(373)), common.BigToHash(big.NewInt(1000000000000000000))},
	//insured-finance 18
	common.HexToAddress("0x159751323a9e0415dd3d6d42a1212fe9f4a0848c"): {common.BigToHash(big.NewInt(453)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tenshi-new 18
	common.HexToAddress("0x52662717e448be36cb54588499d5a8328bd95292"): {common.BigToHash(big.NewInt(88)), common.BigToHash(big.NewInt(1000000000000000000))},
	//frax 18
	common.HexToAddress("0x853d955acef822db058eb8505911ed77f175b99e"): {common.BigToHash(big.NewInt(10100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//smartkey 8
	common.HexToAddress("0x06A01a4d579479Dd5D884EBf61A31727A3d8D442"): {common.BigToHash(big.NewInt(999)), common.BigToHash(big.NewInt(100000000))},
	//nord-finance 18
	common.HexToAddress("0x6e9730ecffbed43fd876a264c982e254ef05a0de"): {common.BigToHash(big.NewInt(27799)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unore 18
	common.HexToAddress("0x474021845c4643113458ea4414bdb7fb74a01a77"): {common.BigToHash(big.NewInt(2808)), common.BigToHash(big.NewInt(1000000000000000000))},
	//masq 18
	common.HexToAddress("0x06f3c323f0238c72bf35011071f2b5b7f43a054c"): {common.BigToHash(big.NewInt(1822)), common.BigToHash(big.NewInt(1000000000000000000))},
	//revv 18
	common.HexToAddress("0x557b933a7c2c45672b610f8954a3deb39a51a8ca"): {common.BigToHash(big.NewInt(1317)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dextf-protocol 18
	common.HexToAddress("0x5F64Ab1544D28732F0A24F4713c2C8ec0dA089f0"): {common.BigToHash(big.NewInt(772)), common.BigToHash(big.NewInt(1000000000000000000))},
	//vent-finance 18
	common.HexToAddress("0x5f0bc16d50f72d10b719dbf6845de2e599eb5624"): {common.BigToHash(big.NewInt(3108)), common.BigToHash(big.NewInt(1000000000000000000))},
	//coreto 18
	common.HexToAddress("0x9C2dc0c3CC2BADdE84B0025Cf4df1c5aF288D835"): {common.BigToHash(big.NewInt(172)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shibnaki 18
	common.HexToAddress("0x85122a589fc2a92cbe6c6606e2b6661fedfa67ee"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gains-farm-v2 18
	common.HexToAddress("0x831091dA075665168E01898c6DAC004A867f1e1B"): {common.BigToHash(big.NewInt(41897929)), common.BigToHash(big.NewInt(1000000000000000000))},
	//paxos-standard 18
	common.HexToAddress("0x8e870d67f660d95d5be530380d0ec0bd388289e1"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//piccolo-inu 9
	common.HexToAddress("0x3a1311b8c404629e38f61d566cefefed083b9670"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//dovu 18
	common.HexToAddress("0xac3211a5025414af2866ff09c23fc18bc97e79b1"): {common.BigToHash(big.NewInt(109)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mandox 9
	common.HexToAddress("0xAFbF03181833aB4E8DEc24D708a2a24c2bAaa4a4"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//revomon 18
	common.HexToAddress("0x155040625D7ae3e9caDA9a73E3E44f76D3Ed1409"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//deku-inu 9
	common.HexToAddress("0xa1a88cea335edaf30ce90f103f1434a773ea46bd"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//robonomics-network 9
	common.HexToAddress("0x7de91b204c1c737bcee6f000aaa6569cf7061cb7"): {common.BigToHash(big.NewInt(101300)), common.BigToHash(big.NewInt(1000000000))},
	//foam 18
	common.HexToAddress("0x4946fcea7c692606e8908002e55a582af44ac121"): {common.BigToHash(big.NewInt(491)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hiko-inu 9
	common.HexToAddress("0x1579d058918f339c945802ffac81762e432cd0b8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//yaxis 18
	common.HexToAddress("0x0ada190c81b814548ddc2f6adc4a689ce7c1fe73"): {common.BigToHash(big.NewInt(11187)), common.BigToHash(big.NewInt(1000000000000000000))},
	//finance-vote 18
	common.HexToAddress("0x45080a6531d671DDFf20DB42f93792a489685e32"): {common.BigToHash(big.NewInt(102)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mobiepay 18
	common.HexToAddress("0x71ba91dc68c6a206db0a6a92b4b1de3f9271432d"): {common.BigToHash(big.NewInt(51)), common.BigToHash(big.NewInt(1000000000000000000))},
	//synapse-network 18
	common.HexToAddress("0x6911f552842236bd9e8ea8ddbb3fb414e2c5fa9d"): {common.BigToHash(big.NewInt(2744)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shibrwd 18
	common.HexToAddress("0xa518c9f3724cced4715e6813858dc2ce9b21ed78"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//susd 18
	common.HexToAddress("0x57Ab1ec28D129707052df4dF418D58a2D46d5f51"): {common.BigToHash(big.NewInt(9865)), common.BigToHash(big.NewInt(1000000000000000000))},
	//amasa 18
	common.HexToAddress("0x65a8fbA02F641a13Bb7B01d5E1129b0521004f52"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//renzec 8
	common.HexToAddress("0x1c5db575e2ff833e46a2e9864c22f4b22e0b37c2"): {common.BigToHash(big.NewInt(1461841)), common.BigToHash(big.NewInt(100000000))},
	//jupiter 18
	common.HexToAddress("0x4B1E80cAC91e2216EEb63e29B957eB91Ae9C2Be8"): {common.BigToHash(big.NewInt(119)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cyberfi 18
	common.HexToAddress("0x63b4f3e3fa4e438698ce330e365e831f7ccd1ef4"): {common.BigToHash(big.NewInt(44139)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bluesparrow-token 9
	common.HexToAddress("0x4d67edef87a5ff910954899f4e5a0aaf107afd42"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//lympo-market-token 18
	common.HexToAddress("0x327673ae6b33bd3d90f0096870059994f30dc8af"): {common.BigToHash(big.NewInt(1220)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cryptomeda 18
	common.HexToAddress("0x6286A9e6f7e745A6D884561D88F94542d6715698"): {common.BigToHash(big.NewInt(122)), common.BigToHash(big.NewInt(1000000000000000000))},
	//friends-with-benefits-pro 18
	common.HexToAddress("0x35bd01fc9d6d5d81ca9e055db88dc49aa2c699a8"): {common.BigToHash(big.NewInt(573503)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nucypher 18
	common.HexToAddress("0x4fe83213d56308330ec302a8bd641f1d0113a4cc"): {common.BigToHash(big.NewInt(6441)), common.BigToHash(big.NewInt(1000000000000000000))},
	//minishib-token 9
	common.HexToAddress("0x3c5bda020caa1350a7b4e6e013a2516423c2800f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//pepemon-pepeballs 18
	common.HexToAddress("0x4d2ee5dae46c86da2ff521f7657dad98834f97b8"): {common.BigToHash(big.NewInt(640874)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pulse-token 18
	common.HexToAddress("0x52a047ee205701895ee06a375492490ec9c597ce"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fortune 9
	common.HexToAddress("0x9f009d03e1b7f02065017c90e8e0d5cb378eb015"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//schrodinger 9
	common.HexToAddress("0x2c33b28527a63cdf13c0b24ce4cf5bf9c9fb3bc6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//swipe 18
	common.HexToAddress("0x8ce9137d39326ad0cd6491fb5cc0cba0e089b6a9"): {common.BigToHash(big.NewInt(16299)), common.BigToHash(big.NewInt(1000000000000000000))},
	//superbid 18
	common.HexToAddress("0x0563dce613d559a47877ffd1593549fb9d3510d6"): {common.BigToHash(big.NewInt(8077)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bright-union 18
	common.HexToAddress("0xbeab712832112bd7664226db7cd025b153d3af55"): {common.BigToHash(big.NewInt(891)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mintyswap 9
	common.HexToAddress("0xbbd900e05b4af2124390d206f70bc4e583b1be85"): {common.BigToHash(big.NewInt(688)), common.BigToHash(big.NewInt(1000000000))},
	//formation-fi 18
	common.HexToAddress("0x21381e026ad6d8266244f2a583b35f9e4413fa2a"): {common.BigToHash(big.NewInt(505)), common.BigToHash(big.NewInt(1000000000000000000))},
	//blockchain-cuties-universe 18
	common.HexToAddress("0x14da7b27b2e0fedefe0a664118b0c9bc68e2e9af"): {common.BigToHash(big.NewInt(8050)), common.BigToHash(big.NewInt(1000000000000000000))},
	//depay 18
	common.HexToAddress("0xa0bEd124a09ac2Bd941b10349d8d224fe3c955eb"): {common.BigToHash(big.NewInt(6889)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cardstack 18
	common.HexToAddress("0x954b890704693af242613edef1b603825afcd708"): {common.BigToHash(big.NewInt(76)), common.BigToHash(big.NewInt(1000000000000000000))},
	//darwinia-network 18
	common.HexToAddress("0x9469d013805bffb7d3debe5e7839237e535ec483"): {common.BigToHash(big.NewInt(365)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tradestars 18
	common.HexToAddress("0x734c90044a0ba31b3f2e640c10dc5d3540499bfd"): {common.BigToHash(big.NewInt(1729)), common.BigToHash(big.NewInt(1000000000000000000))},
	//blockswap-network 18
	common.HexToAddress("0x7d4b1d793239707445305d8d2456d2c735f6b25b"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kira-network 6
	common.HexToAddress("0x16980b3b4a3f9d89e33311b5aa8f80303e5ca4f8"): {common.BigToHash(big.NewInt(3754)), common.BigToHash(big.NewInt(1000000))},
	//beholder 18
	common.HexToAddress("0x155ff1A85F440EE0A382eA949f24CE4E0b751c65"): {common.BigToHash(big.NewInt(4828)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dvision-network 18
	common.HexToAddress("0x10633216e7e8281e33c86f02bf8e565a635d9770"): {common.BigToHash(big.NewInt(9062)), common.BigToHash(big.NewInt(1000000000000000000))},
	//quid-ika 9
	common.HexToAddress("0x9d38f670d15c14716be1f109a4f453e966a2b6d4"): {common.BigToHash(big.NewInt(185)), common.BigToHash(big.NewInt(1000000000))},
	//wrapped-nxm 18
	common.HexToAddress("0x0d438f3b5175bebc262bf23753c1e53d03432bde"): {common.BigToHash(big.NewInt(556625)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unilayer 18
	common.HexToAddress("0x0fF6ffcFDa92c53F615a4A75D982f399C989366b"): {common.BigToHash(big.NewInt(2802)), common.BigToHash(big.NewInt(1000000000000000000))},
	//morpheus-labs 18
	common.HexToAddress("0x4a527d8fc13c5203ab24ba0944f4cb14658d1db6"): {common.BigToHash(big.NewInt(270)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sheesha-finance-erc20 18
	common.HexToAddress("0x232FB065D9d24c34708eeDbF03724f2e95ABE768"): {common.BigToHash(big.NewInt(1456037)), common.BigToHash(big.NewInt(1000000000000000000))},
	//get-protocol 18
	common.HexToAddress("0x8a854288a5976036a725879164ca3e91d30c6a1b"): {common.BigToHash(big.NewInt(17200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chain 18
	common.HexToAddress("0x41C37A4683d6a05adB31c39D71348A8403B13Ca9"): {common.BigToHash(big.NewInt(1054000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ethereummax 18
	common.HexToAddress("0x15874d65e649880c2614e7a480cb7c9a55787ff6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wrapped-gen-0-cryptokitties 18
	common.HexToAddress("0xa10740ff9ff6852eac84cdcff9184e1d6d27c057"): {common.BigToHash(big.NewInt(3256800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tixl-new 18
	common.HexToAddress("0x8eEF5a82E6Aa222a60F009ac18c24EE12dBf4b41"): {common.BigToHash(big.NewInt(973)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pawthereum 9
	common.HexToAddress("0xaecc217a749c2405b5ebc9857a16d58bdc1c367f"): {common.BigToHash(big.NewInt(57)), common.BigToHash(big.NewInt(1000000000))},
	//myneighboralice 6
	common.HexToAddress("0xAC51066d7bEC65Dc4589368da368b212745d63E8"): {common.BigToHash(big.NewInt(115399)), common.BigToHash(big.NewInt(1000000))},
	//centaurify 18
	common.HexToAddress("0x08ba718f288c3b12b01146816bef9fa03cc635bc"): {common.BigToHash(big.NewInt(152)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shira-inu 9
	common.HexToAddress("0x04a5198063e45d84b1999516d3228167146417a6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//sovryn 18
	common.HexToAddress("0xbdab72602e9ad40fc6a6852caf43258113b8f7a5"): {common.BigToHash(big.NewInt(74832)), common.BigToHash(big.NewInt(1000000000000000000))},
	//charged-particles 18
	common.HexToAddress("0x02d3a27ac3f55d5d91fb0f52759842696a864217"): {common.BigToHash(big.NewInt(7735)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ksm-starter 18
	common.HexToAddress("0xBc17729fDf562723f0267F79FF25aDE441056d87"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gamecredits 18
	common.HexToAddress("0x63f88a2298a5c4aee3c216aa6d926b184a4b2437"): {common.BigToHash(big.NewInt(1351)), common.BigToHash(big.NewInt(1000000000000000000))},
	//metronome 18
	common.HexToAddress("0xa3d58c4e56fedcae3a7c43a725aee9a71f0ece4e"): {common.BigToHash(big.NewInt(38600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bird-money 18
	common.HexToAddress("0x70401dfd142a16dc7031c56e862fc88cb9537ce0"): {common.BigToHash(big.NewInt(753015)), common.BigToHash(big.NewInt(1000000000000000000))},
	//astroelon 9
	common.HexToAddress("0x97b65710d03e12775189f0d113202cc1443b0aa2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//btse 8
	common.HexToAddress("0x666d875c600aa06ac1cf15641361dec3b00432ef"): {common.BigToHash(big.NewInt(65300)), common.BigToHash(big.NewInt(100000000))},
	//paralink-network 18
	common.HexToAddress("0x3a8d5BC8A8948b68DfC0Ce9C14aC4150e083518c"): {common.BigToHash(big.NewInt(149)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kunoichix 9
	common.HexToAddress("0x0b5ECBb411d8FE829e5eAc253EE1F2Dc05D8d1Ae"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//ureeqa 18
	common.HexToAddress("0x1735Db6AB5BAa19eA55d0AdcEeD7bcDc008B3136"): {common.BigToHash(big.NewInt(1397)), common.BigToHash(big.NewInt(1000000000000000000))},
	//benchmark-protocol 9
	common.HexToAddress("0x67c597624b17b16fb77959217360b7cd18284253"): {common.BigToHash(big.NewInt(14872)), common.BigToHash(big.NewInt(1000000000))},
	//ovr 18
	common.HexToAddress("0x21bfbda47a0b4b5b1248c767ee49f7caa9b23697"): {common.BigToHash(big.NewInt(24100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gamezone 18
	common.HexToAddress("0xb6adb74efb5801160ff749b1985fd3bd5000e938"): {common.BigToHash(big.NewInt(3862)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defi-yield-protocol 18
	common.HexToAddress("0x961C8c0B1aaD0c0b10a51FeF6a867E3091BCef17"): {common.BigToHash(big.NewInt(4566)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dev-protocol 18
	common.HexToAddress("0x5caf454ba92e6f2c929df14667ee360ed9fd5b26"): {common.BigToHash(big.NewInt(15800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//matrix-samurai-rbxs 18
	common.HexToAddress("0xa9639160481b625ba43677be753e0a70bf58c647"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dxdao 18
	common.HexToAddress("0xa1d65e8fb6e87b60feccbc582f7f97804b725521"): {common.BigToHash(big.NewInt(5428640)), common.BigToHash(big.NewInt(1000000000000000000))},
	//umbria-network 18
	common.HexToAddress("0xa4bbe66f151b22b167127c770016b15ff97dd35c"): {common.BigToHash(big.NewInt(20742)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bankless-dao 18
	common.HexToAddress("0x2d94aa3e47d9d5024503ca8491fce9a2fb4da198"): {common.BigToHash(big.NewInt(733)), common.BigToHash(big.NewInt(1000000000000000000))},
	//arcona 18
	common.HexToAddress("0x0f71b8de197a1c84d31de0f1fa7926c365f052b3"): {common.BigToHash(big.NewInt(7181)), common.BigToHash(big.NewInt(1000000000000000000))},
	//grey-token 9
	common.HexToAddress("0x9b2D81A1AE36E8e66A0875053429816f0B6b829E"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//moonie-nft 18
	common.HexToAddress("0xA6F7645ed967FAF708A614a2fcA8D4790138586f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//plasma-finance 18
	common.HexToAddress("0x054d64b73d3d8a21af3d764efd76bcaa774f3bb2"): {common.BigToHash(big.NewInt(644)), common.BigToHash(big.NewInt(1000000000000000000))},
	//crowns 18
	common.HexToAddress("0xac0104cca91d167873b8601d2e71eb3d4d8c33e0"): {common.BigToHash(big.NewInt(64500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//archangel-token 9
	common.HexToAddress("0x36e43065e977bc72cb86dbd8405fae7057cdc7fd"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//unimex-network 18
	common.HexToAddress("0x10be9a8dae441d276a5027936c3aaded2d82bc15"): {common.BigToHash(big.NewInt(3176)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rlc 9
	common.HexToAddress("0x607f4c5bb672230e8672085532f7e901544a7375"): {common.BigToHash(big.NewInt(28700)), common.BigToHash(big.NewInt(1000000000))},
	//launchpool 18
	common.HexToAddress("0x6149c26cd2f7b5ccdb32029af817123f6e37df5b"): {common.BigToHash(big.NewInt(25900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//olyseum 18
	common.HexToAddress("0x6595b8fd9c920c81500dca94e53cdc712513fb1f"): {common.BigToHash(big.NewInt(52)), common.BigToHash(big.NewInt(1000000000000000000))},
	//balancer 18
	common.HexToAddress("0xba100000625a3754423978a60c9317c58a424e3D"): {common.BigToHash(big.NewInt(179500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polytrade 18
	common.HexToAddress("0x6e5970DBd6fc7eb1f29C6D2eDF2bC4c36124C0C1"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//alpaca-city 18
	common.HexToAddress("0x7cA4408137eb639570F8E647d9bD7B7E8717514A"): {common.BigToHash(big.NewInt(2518)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dos-network 18
	common.HexToAddress("0x0A913beaD80F321E7Ac35285Ee10d9d922659cB7"): {common.BigToHash(big.NewInt(162)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tontoken 18
	common.HexToAddress("0x6a6c2ada3ce053561c2fbc3ee211f23d9b8c520a"): {common.BigToHash(big.NewInt(334)), common.BigToHash(big.NewInt(1000000000000000000))},
	//koinos 8
	common.HexToAddress("0x66d28cb58487a7609877550e1a34691810a6b9fc"): {common.BigToHash(big.NewInt(6863)), common.BigToHash(big.NewInt(100000000))},
	//nitro-league 18
	common.HexToAddress("0x0335A7610D817aeCA1bEBbEfbd392ecC2eD587B8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//adx-net 18
	common.HexToAddress("0xade00c28244d5ce17d72e40330b1c318cd12b7c3"): {common.BigToHash(big.NewInt(5116)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yeager-inu 9
	common.HexToAddress("0x8966f05d78f5c6ede8e964df705847fe2b6045b1"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//shiba-viking 18
	common.HexToAddress("0x040a856f2c59bb49166210a54a55d0b2599b46d8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//maps 6
	common.HexToAddress("0x2b915b505c017abb1547aa5ab355fbe69865cc6d"): {common.BigToHash(big.NewInt(2501)), common.BigToHash(big.NewInt(1000000))},
	//continuum-world 18
	common.HexToAddress("0xb19dd661f076998e3b0456935092a233e12c2280"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//azuki 18
	common.HexToAddress("0x910524678C0B1B23FFB9285a81f99C29C11CBaEd"): {common.BigToHash(big.NewInt(289)), common.BigToHash(big.NewInt(1000000000000000000))},
	//index-cooperative 18
	common.HexToAddress("0x0954906da0Bf32d5479e25f46056d22f08464cab"): {common.BigToHash(big.NewInt(131052)), common.BigToHash(big.NewInt(1000000000000000000))},
	//spice-dao 18
	common.HexToAddress("0x9b6db7597a74602a5a806e33408e7e2dafa58193"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//poolz-finance 18
	common.HexToAddress("0x69a95185ee2a045cdc4bcd1b1df10710395e4e23"): {common.BigToHash(big.NewInt(58800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//crypto-com-coin 8
	common.HexToAddress("0xa0b73e1ff0b80914ab6fe0444e65848c4c34450b"): {common.BigToHash(big.NewInt(4721)), common.BigToHash(big.NewInt(100000000))},
	//darwinia-commitment-token 18
	common.HexToAddress("0x9f284e1337a815fe77d2ff4ae46544645b20c5ff"): {common.BigToHash(big.NewInt(487600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//multi-chain-capital 9
	common.HexToAddress("0x1a7981d87e3b6a95c1516eb820e223fe979896b3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//lithium 18
	common.HexToAddress("0x188e817b02e635d482ae4d81e25dda98a97c4a42"): {common.BigToHash(big.NewInt(112)), common.BigToHash(big.NewInt(1000000000000000000))},
	//voxel-x-network 18
	common.HexToAddress("0x16CC8367055aE7e9157DBcB9d86Fd6CE82522b31"): {common.BigToHash(big.NewInt(995)), common.BigToHash(big.NewInt(1000000000000000000))},
	//evedo 18
	common.HexToAddress("0x5aaefe84e0fb3dd1f0fcff6fa7468124986b91bd"): {common.BigToHash(big.NewInt(937)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kiki 18
	common.HexToAddress("0x369b77bbeeee50e6ea206dcf41ee670c47360055"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hyprr 18
	common.HexToAddress("0x12f649a9e821f90bb143089a6e56846945892ffb"): {common.BigToHash(big.NewInt(42)), common.BigToHash(big.NewInt(1000000000000000000))},
	//raze-network 18
	common.HexToAddress("0x5Eaa69B29f99C84Fe5dE8200340b4e9b4Ab38EaC"): {common.BigToHash(big.NewInt(814)), common.BigToHash(big.NewInt(1000000000000000000))},
	//uniris 18
	common.HexToAddress("0x8a3d77e9d6968b780564936d15B09805827C21fa"): {common.BigToHash(big.NewInt(1957)), common.BigToHash(big.NewInt(1000000000000000000))},
	//steth 18
	common.HexToAddress("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"): {common.BigToHash(big.NewInt(32179400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//block-duelers 18
	common.HexToAddress("0x7bce667ef12023dc5f8577d015a2f09d99a5ef58"): {common.BigToHash(big.NewInt(190100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//e1337 4
	common.HexToAddress("0x35872fea6a4843facbcdbce99e3b69596a3680b8"): {common.BigToHash(big.NewInt(8583)), common.BigToHash(big.NewInt(10000))},
	//triall 18
	common.HexToAddress("0x58f9102bf53cf186682bd9a281d3cd3c616eec41"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//versoview 18
	common.HexToAddress("0x755be920943eA95e39eE2DC437b268917B580D6e"): {common.BigToHash(big.NewInt(1273)), common.BigToHash(big.NewInt(1000000000000000000))},
	//theos 18
	common.HexToAddress("0x9e10f61749c4952c320412a6b26901605ff6da1d"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polkamon 18
	common.HexToAddress("0x1796ae0b0fa4862485106a0de9b654eFE301D0b2"): {common.BigToHash(big.NewInt(53400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defil 18
	common.HexToAddress("0x09ce2b746c32528b7d864a1e3979bd97d2f095ab"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//naraka-token 9
	common.HexToAddress("0x8e3fe7cdf4ebb605bbbac3a43d76ea757f7f06e2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//fomoeth 9
	common.HexToAddress("0x8a65b987d9813f0a97446eda0de918b2573ae406"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//less-network 18
	common.HexToAddress("0x62786eeacc9246b4018e0146cb7a3efeacd9459d"): {common.BigToHash(big.NewInt(191)), common.BigToHash(big.NewInt(1000000000000000000))},
	//degate 18
	common.HexToAddress("0x53c8395465a84955c95159814461466053dedede"): {common.BigToHash(big.NewInt(2185)), common.BigToHash(big.NewInt(1000000000000000000))},
	//peanut 18
	common.HexToAddress("0x89bd2e7e388fab44ae88bef4e1ad12b4f1e0911c"): {common.BigToHash(big.NewInt(2275)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wgmi 18
	common.HexToAddress("0x20f6a313cb250062331fe70b9567e3ee5f01888b"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//metavpad 18
	common.HexToAddress("0x62858686119135cc00C4A3102b436a0eB314D402"): {common.BigToHash(big.NewInt(3323)), common.BigToHash(big.NewInt(1000000000000000000))},
	//doubledice-token 18
	common.HexToAddress("0x4e08f03079c5cd3083ea331ec61bcc87538b7665"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shadows 18
	common.HexToAddress("0x661ab0ed68000491d98c796146bcf28c20d7c559"): {common.BigToHash(big.NewInt(974)), common.BigToHash(big.NewInt(1000000000000000000))},
	//iagon 18
	common.HexToAddress("0x40eb746dee876ac1e78697b7ca85142d178a1fc8"): {common.BigToHash(big.NewInt(366)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ix-swap 18
	common.HexToAddress("0x73d7c860998ca3c01ce8c808f5577d94d545d1b4"): {common.BigToHash(big.NewInt(1499)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bluzelle 18
	common.HexToAddress("0x5732046a883704404f284ce41ffadd5b007fd668"): {common.BigToHash(big.NewInt(1903)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cat-token 18
	common.HexToAddress("0x56015bbe3c01fe05bc30a8a9a9fd9a88917e7db3"): {common.BigToHash(big.NewInt(2827)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bunnyverse 18
	common.HexToAddress("0x072987d5b36ad8d45552aed98879a7101ccdd749"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hord 18
	common.HexToAddress("0x43a96962254855f16b925556f9e97be436a43448"): {common.BigToHash(big.NewInt(1097)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mxc 18
	common.HexToAddress("0x5ca381bbfb58f0092df149bd3d243b08b9a8386e"): {common.BigToHash(big.NewInt(625)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sekuritance 18
	common.HexToAddress("0x887168120cb89fb06f3e74dc4af20d67df0977f6"): {common.BigToHash(big.NewInt(80)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nil-coin 8
	common.HexToAddress("0x0eb638648207d00b9025684d13b1cb53806debe4"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100000000))},
	//locgame 18
	common.HexToAddress("0x60eb57d085c59932d5faa6c6026268a4386927d0"): {common.BigToHash(big.NewInt(1082)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unitrade 18
	common.HexToAddress("0x6f87d756daf0503d08eb8993686c7fc01dc44fb1"): {common.BigToHash(big.NewInt(854)), common.BigToHash(big.NewInt(1000000000000000000))},
	//official-crypto-cowboy-token 18
	common.HexToAddress("0x95a1796437bad6502d1c1cce165cd76e522409a9"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//origin-protocol 18
	common.HexToAddress("0x8207c1ffc5b6804f6024322ccf34f29c3541ae26"): {common.BigToHash(big.NewInt(5581)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dexkit 18
	common.HexToAddress("0x7866e48c74cbfb8183cd1a929cd9b95a7a5cb4f4"): {common.BigToHash(big.NewInt(9708)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sator 9
	common.HexToAddress("0x3EF389f264e07fFF3106A3926F2a166d1393086F"): {common.BigToHash(big.NewInt(1318)), common.BigToHash(big.NewInt(1000000000))},
	//node-runners 18
	common.HexToAddress("0x739763a258640919981F9bA610AE65492455bE53"): {common.BigToHash(big.NewInt(320500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defiville 18
	common.HexToAddress("0x20a68f9e34076b2dc15ce726d7eebb83b694702d"): {common.BigToHash(big.NewInt(10000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nftlootbox 18
	common.HexToAddress("0x7b3D36Eb606f873A75A6aB68f8c999848B04F935"): {common.BigToHash(big.NewInt(580400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//spike-inu 9
	common.HexToAddress("0x0f3debf94483beecbfd20167c946a61ea62d000f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//dego-finance 18
	common.HexToAddress("0x88ef27e69108b2633f8e1c184cc37940a075cc02"): {common.BigToHash(big.NewInt(53118)), common.BigToHash(big.NewInt(1000000000000000000))},
	//phala-network 18
	common.HexToAddress("0x6c5bA91642F10282b576d91922Ae6448C9d52f4E"): {common.BigToHash(big.NewInt(3741)), common.BigToHash(big.NewInt(1000000000000000000))},
	//blockzerolabs 18
	common.HexToAddress("0x0f7F961648aE6Db43C75663aC7E5414Eb79b5704"): {common.BigToHash(big.NewInt(1025)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ore-network 18
	common.HexToAddress("0x4f640F2529ee0cF119A2881485845FA8e61A782A"): {common.BigToHash(big.NewInt(724)), common.BigToHash(big.NewInt(1000000000000000000))},
	//beyond-finance 18
	common.HexToAddress("0x4bb3205bf648b7f59ef90dee0f1b62f6116bc7ca"): {common.BigToHash(big.NewInt(4902)), common.BigToHash(big.NewInt(1000000000000000000))},
	//huobi-token 18
	common.HexToAddress("0x6f259637dcd74c767781e37bc6133cd6a68aa161"): {common.BigToHash(big.NewInt(90200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//compound 18
	common.HexToAddress("0xc00e94cb662c3520282e6f5717214004a7f26888"): {common.BigToHash(big.NewInt(1975200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polyswarm 18
	common.HexToAddress("0x9e46a38f5daabe8683e10793b06749eef7d733d1"): {common.BigToHash(big.NewInt(245)), common.BigToHash(big.NewInt(1000000000000000000))},
	//numeraire 18
	common.HexToAddress("0x1776e1F26f98b1A5dF9cD347953a26dd3Cb46671"): {common.BigToHash(big.NewInt(282200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rupiah-token 2
	common.HexToAddress("0x998FFE1E43fAcffb941dc337dD0468d52bA5b48A"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(100))},
	//daostack 18
	common.HexToAddress("0x543ff227f64aa17ea132bf9886cab5db55dcaddf"): {common.BigToHash(big.NewInt(357)), common.BigToHash(big.NewInt(1000000000000000000))},
	//airswap 4
	common.HexToAddress("0x27054b13b1b798b345b591a4d22e6562d47ea75a"): {common.BigToHash(big.NewInt(2337)), common.BigToHash(big.NewInt(10000))},
	//chihiro-inu 9
	common.HexToAddress("0x35156b404c3f9bdaf45ab65ba315419bcde3775c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//ptokens-btc 18
	common.HexToAddress("0x5228a22e72ccc52d415ecfd199f99d0665e7733b"): {common.BigToHash(big.NewInt(396080000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sparkpoint 18
	common.HexToAddress("0x0488401c3f535193fa8df029d9ffe615a06e74e6"): {common.BigToHash(big.NewInt(11)), common.BigToHash(big.NewInt(1000000000000000000))},
	//argoapp 18
	common.HexToAddress("0x28cca76f6e8ec81e4550ecd761f899110b060e97"): {common.BigToHash(big.NewInt(1680)), common.BigToHash(big.NewInt(1000000000000000000))},
	//swapp-protocol 18
	common.HexToAddress("0x8cb924583681cbfe487a62140a994a49f833c244"): {common.BigToHash(big.NewInt(82)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dotmoovs 18
	common.HexToAddress("0x24ec2ca132abf8f6f8a6e24a1b97943e31f256a7"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//blackdragon 18
	common.HexToAddress("0x4Efe8665e564bF454cCF5C90Ee16817F7485d5Cf"): {common.BigToHash(big.NewInt(109500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//neoworld-cash 18
	common.HexToAddress("0x4b94c8567763654101f690cf4d54957206383b75"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gnosis-gno 18
	common.HexToAddress("0x6810e776880c02933d47db1b9fc05908e5386b96"): {common.BigToHash(big.NewInt(4531100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//measurable-data-token 18
	common.HexToAddress("0x814e0908b12a99fecf5bc101bb5d0b8b5cdf7d26"): {common.BigToHash(big.NewInt(934)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kounotori 9
	common.HexToAddress("0x616ef40d55c0d2c506f4d6873bda8090b79bf8fc"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//mettalex 18
	common.HexToAddress("0x2e1e15c44ffe4df6a0cb7371cd00d5028e571d14"): {common.BigToHash(big.NewInt(10116)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ridge 9
	common.HexToAddress("0x64609A845Ad463d07ee51e91a88D1461C3Dc3165"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//digital-fitness 18
	common.HexToAddress("0x84cffa78b2fbbeec8c37391d2b12a04d2030845e"): {common.BigToHash(big.NewInt(315)), common.BigToHash(big.NewInt(1000000000000000000))},
	//the-citadel 9
	common.HexToAddress("0x849ba2278cdae7fa7006c0661fea1c35d5af3336"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//the-rare-antiquities-token 18
	common.HexToAddress("0x6460b9954a05714a1a8d36bac6d8bc9b657352d7"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kaiba-inu 9
	common.HexToAddress("0x8bb048845ee0d75be8e07954b2e1e5b51b64b442"): {common.BigToHash(big.NewInt(300)), common.BigToHash(big.NewInt(1000000000))},
	//tower-token 18
	common.HexToAddress("0x1c9922314ed1415c95b9fd453c3818fd41867d0b"): {common.BigToHash(big.NewInt(449)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bitant 18
	common.HexToAddress("0x15Ee120fD69BEc86C1d38502299af7366a41D1a6"): {common.BigToHash(big.NewInt(9)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ally-direct-token 18
	common.HexToAddress("0x9d561d63375672ABd02119b9Bc4FB90EB9E307Ca"): {common.BigToHash(big.NewInt(51)), common.BigToHash(big.NewInt(1000000000000000000))},
	//efforce 18
	common.HexToAddress("0x34950ff2b487d9e5282c5ab342d08a2f712eb79f"): {common.BigToHash(big.NewInt(2118)), common.BigToHash(big.NewInt(1000000000000000000))},
	//oxen 9
	common.HexToAddress("0xd1e2d5085b39b80c9948aeb1b9aa83af6756bcc5"): {common.BigToHash(big.NewInt(5135)), common.BigToHash(big.NewInt(1000000000))},
	//unistake 18
	common.HexToAddress("0x9ed8e7c9604790f7ec589f99b94361d8aab64e5e"): {common.BigToHash(big.NewInt(158)), common.BigToHash(big.NewInt(1000000000000000000))},
	//decentralized-nations 18
	common.HexToAddress("0x15f0eedf9ce24fc4b6826e590a8292ce5524a1da"): {common.BigToHash(big.NewInt(19294)), common.BigToHash(big.NewInt(1000000000000000000))},
	//safeswap-governance-token 18
	common.HexToAddress("0x2ecc48ba346a73d7d55aa5a46b5e314d9daa6161"): {common.BigToHash(big.NewInt(247)), common.BigToHash(big.NewInt(1000000000000000000))},
	//zap 18
	common.HexToAddress("0x6781a0f84c7e9e846dcb84a9a5bd49333067b104"): {common.BigToHash(big.NewInt(151)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bzx-protocol 18
	common.HexToAddress("0x56d811088235F11C8920698a204A5010a788f4b3"): {common.BigToHash(big.NewInt(2612)), common.BigToHash(big.NewInt(1000000000000000000))},
	//digicol 18
	common.HexToAddress("0x63B8b7d4A3EFD0735c4BFFBD95B332a55e4eB851"): {common.BigToHash(big.NewInt(156)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kawakami-inu 18
	common.HexToAddress("0x546aed37d202d607f45cbd2b8c0cad0d25fbe339"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//winry-inu 9
	common.HexToAddress("0x1a87077c4f834884691b8ba4fc808d2ec93a9f30"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//lunr-token 4
	common.HexToAddress("0xA87135285Ae208e22068AcDBFf64B11Ec73EAa5A"): {common.BigToHash(big.NewInt(13300)), common.BigToHash(big.NewInt(10000))},
	//sportx 18
	common.HexToAddress("0x99fe3b1391503a1bc1788051347a1324bff41452"): {common.BigToHash(big.NewInt(4813)), common.BigToHash(big.NewInt(1000000000000000000))},
	//degen-index 18
	common.HexToAddress("0x126c121f99e1e211df2e5f8de2d96fa36647c855"): {common.BigToHash(big.NewInt(44052)), common.BigToHash(big.NewInt(1000000000000000000))},
	//redpanda 9
	common.HexToAddress("0x514cdb9cd8a2fb2bdcf7a3b8ddd098caf466e548"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//axl-inu 18
	common.HexToAddress("0x25b24b3c47918b7962b3e49c4f468367f73cc0e0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//santiment 18
	common.HexToAddress("0x7c5a0ce9267ed19b22f8cae653f198e3e8daf098"): {common.BigToHash(big.NewInt(2916)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nftify 18
	common.HexToAddress("0xaCbd826394189Cf2623C6DF98a18b41fC8fFC16D"): {common.BigToHash(big.NewInt(509)), common.BigToHash(big.NewInt(1000000000000000000))},
	//oxygen 6
	common.HexToAddress("0x965697b4ef02f0de01384d0d4f9f782b1670c163"): {common.BigToHash(big.NewInt(6075)), common.BigToHash(big.NewInt(1000000))},
	//keyfi 18
	common.HexToAddress("0xb8647e90c0645152fccf4d9abb6b59eb4aa99052"): {common.BigToHash(big.NewInt(7065)), common.BigToHash(big.NewInt(1000000000000000000))},
	//serum 6
	common.HexToAddress("0x476c5e26a75bd202a9683ffd34359c0cc15be0ff"): {common.BigToHash(big.NewInt(31800)), common.BigToHash(big.NewInt(1000000))},
	//allbridge 18
	common.HexToAddress("0xa11bd36801d8fa4448f0ac4ea7a62e3634ce8c7c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wrapped-virgin-gen-0-cryptokitties 18
	common.HexToAddress("0x25c7b64a93eb1261e130ec21a3e9918caa38b611"): {common.BigToHash(big.NewInt(3833899)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hanzo-inu 9
	common.HexToAddress("0x239dc02a28a0774738463e06245544a72745d5c5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//south-african-tether 18
	common.HexToAddress("0x48f07301e9e29c3c38a80ae8d9ae771f224f1054"): {common.BigToHash(big.NewInt(603)), common.BigToHash(big.NewInt(1000000000000000000))},
	//spheroid-universe 18
	common.HexToAddress("0xa0cf46eb152656c7090e769916eb44a138aaa406"): {common.BigToHash(big.NewInt(719)), common.BigToHash(big.NewInt(1000000000000000000))},
	//4thpillar-technologies 18
	common.HexToAddress("0x4730fb1463a6f1f44aeb45f6c5c422427f37f4d0"): {common.BigToHash(big.NewInt(69)), common.BigToHash(big.NewInt(1000000000000000000))},
	//zuz-protocol 18
	common.HexToAddress("0x202f1877e1db1120ca3e9a98c5d505e7f035c249"): {common.BigToHash(big.NewInt(3216)), common.BigToHash(big.NewInt(1000000000000000000))},
	//metadoge-token 18
	common.HexToAddress("0x8530b66ca3ddf50e0447eae8ad7ea7d5e62762ed"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//disbalancer 18
	common.HexToAddress("0x7fbec0bb6a7152e77c30d005b5d49cbc08a602c3"): {common.BigToHash(big.NewInt(6221)), common.BigToHash(big.NewInt(1000000000000000000))},
	//plgnet 18
	common.HexToAddress("0x47da5456bc2e1ce391b645ce80f2e97192e4976a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//magickdao 9
	common.HexToAddress("0x6b578f63a40173d85215cc01d6d79e553e8c993c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//vaiot 18
	common.HexToAddress("0x9f801c1f02af03cc240546dadef8e56cd46ea2e9"): {common.BigToHash(big.NewInt(2098)), common.BigToHash(big.NewInt(1000000000000000000))},
	//saja 9
	common.HexToAddress("0x698c6ac9ca5f16cabc5a636d3a619329c0958cba"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//standard-protocol 18
	common.HexToAddress("0x9040e237C3bF18347bb00957Dc22167D0f2b999d"): {common.BigToHash(big.NewInt(3247)), common.BigToHash(big.NewInt(1000000000000000000))},
	//buying-com 2
	common.HexToAddress("0x396ec402b42066864c406d1ac3bc86b575003ed8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100))},
	//dfyn-network 18
	common.HexToAddress("0x9695e0114e12c0d3a3636fab5a18e6b737529023"): {common.BigToHash(big.NewInt(1911)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shoefy 18
	common.HexToAddress("0x0fD67B4ceb9b607Ef206904eC73459c4880132c9"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rickmortydoxx 9
	common.HexToAddress("0x5d29011d843b0b1760c43e10d66f302174bccd1a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//uncl 18
	common.HexToAddress("0x2f4eb47a1b1f4488c71fc10e39a4aa56af33dd49"): {common.BigToHash(big.NewInt(379561)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nexo 18
	common.HexToAddress("0xb62132e35a6c13ee1ee0f84dc5d40bad8d815206"): {common.BigToHash(big.NewInt(21900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hegic 18
	common.HexToAddress("0x584bC13c7D411c00c01A62e8019472dE68768430"): {common.BigToHash(big.NewInt(592)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dao-vc 18
	common.HexToAddress("0x284b59cf2539544559c6efa11e2795e06d535345"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//floki-gold 9
	common.HexToAddress("0x9f9fd5872beb21392f286afc6eb3a0f8154384fc"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//koka-inu 18
	common.HexToAddress("0xac5bf342763248702f4fbd6dc068381a609543a2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//new-year-resolution 18
	common.HexToAddress("0x3eCF9840DEB8e3c395E1941Fc39ceB662BF5A1Dd"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//router-protocol 18
	common.HexToAddress("0x16eccfdbb4ee1a85a33f3a9b21175cd7ae753db4"): {common.BigToHash(big.NewInt(26800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//crypto-perx 18
	common.HexToAddress("0xc6e145421fd494b26dcf2bfeb1b02b7c5721978f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//konomi-network 18
	common.HexToAddress("0x850aAB69f0e0171A9a49dB8BE3E71351c8247Df4"): {common.BigToHash(big.NewInt(2596)), common.BigToHash(big.NewInt(1000000000000000000))},
	//goku 9
	common.HexToAddress("0xa64dfe8d86963151e6496bee513e366f6e42ed79"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//crust-shadow 18
	common.HexToAddress("0x2620638EDA99F9e7E902Ea24a285456EE9438861"): {common.BigToHash(big.NewInt(381)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gamesta 18
	common.HexToAddress("0x55cd00764E85AA3B6b34130C983fFf9eB458250c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xaya 8
	common.HexToAddress("0x6DC02164d75651758aC74435806093E421b64605"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100000000))},
	//workquest 18
	common.HexToAddress("0x06677dc4fe12d3ba3c7ccfd0df8cd45e4d4095bf"): {common.BigToHash(big.NewInt(329)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ethereum-wrapped-filecoin 18
	common.HexToAddress("0x4b7ee45f30767f36f06f79b32bf1fca6f726deda"): {common.BigToHash(big.NewInt(321200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mixmarvel 18
	common.HexToAddress("0x5d285f735998f36631f678ff41fb56a10a4d0429"): {common.BigToHash(big.NewInt(132)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pussy-financial 18
	common.HexToAddress("0x9196e18bc349b1f64bc08784eae259525329a1ad"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//a2dao 18
	common.HexToAddress("0x8052327F1BAF94A9DC8B26b9100f211eE3774f54"): {common.BigToHash(big.NewInt(10200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//totemfi 18
	common.HexToAddress("0x6ff1bfa14a57594a5874b37ff6ac5efbd9f9599a"): {common.BigToHash(big.NewInt(1616)), common.BigToHash(big.NewInt(1000000000000000000))},
	//daoventures 18
	common.HexToAddress("0x77dcE26c03a9B833fc2D7C31C22Da4f42e9d9582"): {common.BigToHash(big.NewInt(573)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bonfi 18
	common.HexToAddress("0x1DE5e000C41C8d35b9f1f4985C23988f05831057"): {common.BigToHash(big.NewInt(21)), common.BigToHash(big.NewInt(1000000000000000000))},
	//impactx 9
	common.HexToAddress("0x5af6ad286c8ed6633284f2f135c4716057d52669"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//energi 18
	common.HexToAddress("0x1416946162b1c2c871a73b07e932d2fb6c932069"): {common.BigToHash(big.NewInt(10800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dark-energy-crystals 3
	common.HexToAddress("0x9393fdc77090f31c7db989390d43f454b1a6e7f3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000))},
	//panda-inu 9
	common.HexToAddress("0xaa0bd7A009b189EAeab81dfA5e899CB137E0Fc3f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//defichain 8
	common.HexToAddress("0x8fc8f8269ebca376d046ce292dc7eac40c8d358a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100000000))},
	//lcx 18
	common.HexToAddress("0x037a54aab062628c9bbae1fdb1583c195585fe41"): {common.BigToHash(big.NewInt(1580)), common.BigToHash(big.NewInt(1000000000000000000))},
	//truepnl 18
	common.HexToAddress("0x9fc8f0ca1668e87294941b7f627e9c15ea06b459"): {common.BigToHash(big.NewInt(1021)), common.BigToHash(big.NewInt(1000000000000000000))},
	//spiderdao 18
	common.HexToAddress("0xbcd4b7de6fde81025f74426d43165a5b0d790fdd"): {common.BigToHash(big.NewInt(85)), common.BigToHash(big.NewInt(1000000000000000000))},
	//portion 18
	common.HexToAddress("0x6D0F5149c502faf215C89ab306ec3E50b15e2892"): {common.BigToHash(big.NewInt(108)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ampleforth-governance-token 18
	common.HexToAddress("0x77fba179c79de5b7653f68b5039af940ada60ce0"): {common.BigToHash(big.NewInt(81900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wagmi-game 18
	common.HexToAddress("0x1e987df68cc13d271e621ec82e050a1bbd62c180"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//0xbtc 8
	common.HexToAddress("0xb6ed7644c69416d67b522e20bc294a9a9b405b31"): {common.BigToHash(big.NewInt(16600)), common.BigToHash(big.NewInt(100000000))},
	//unmarshal-token 18
	common.HexToAddress("0x5a666c7d92E5fA7Edcb6390E4efD6d0CDd69cF37"): {common.BigToHash(big.NewInt(3988)), common.BigToHash(big.NewInt(1000000000000000000))},
	//capital-dao-protocol 18
	common.HexToAddress("0x3c48ca59bf2699e51d4974d4b6d284ae52076e5e"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tokenize-xchange 8
	common.HexToAddress("0x667102BD3413bFEaa3Dffb48fa8288819E480a88"): {common.BigToHash(big.NewInt(75977)), common.BigToHash(big.NewInt(100000000))},
	//tosdis 18
	common.HexToAddress("0x220b71671b649c03714da9c621285943f3cbcdc6"): {common.BigToHash(big.NewInt(189700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//minter-network 18
	common.HexToAddress("0xcafe34bae6f1b23a6b575303edcc0578d2188131"): {common.BigToHash(big.NewInt(28)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bigshortbets 18
	common.HexToAddress("0x131157c6760f78f7ddf877c0019eba175ba4b6f6"): {common.BigToHash(big.NewInt(6010)), common.BigToHash(big.NewInt(1000000000000000000))},
	//band-protocol 18
	common.HexToAddress("0xba11d00c5f74255f56a5e366f4f77f5a186d7f55"): {common.BigToHash(big.NewInt(53700)), common.BigToHash(big.NewInt(1000000000000000000))},
	//trueusd 18
	common.HexToAddress("0x0000000000085d4780B73119b644AE5ecd22b376"): {common.BigToHash(big.NewInt(10100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ghostblade-inu 9
	common.HexToAddress("0x54b8e638aa2c7a6040f2820f8118237a7bfa0c0d"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//chartex 18
	common.HexToAddress("0x1d37986f252d0e349522ea6c3b98cb935495e63e"): {common.BigToHash(big.NewInt(85)), common.BigToHash(big.NewInt(1000000000000000000))},
	//peakdefi 8
	common.HexToAddress("0x630d98424efe0ea27fb1b3ab7741907dffeaad78"): {common.BigToHash(big.NewInt(1077)), common.BigToHash(big.NewInt(100000000))},
	//duck-dao 18
	common.HexToAddress("0xc0ba369c8db6eb3924965e5c4fd0b4c1b91e305f"): {common.BigToHash(big.NewInt(2097)), common.BigToHash(big.NewInt(1000000000000000000))},
	//add-xyz 18
	common.HexToAddress("0x635d081fd8f6670135d8a3640e2cf78220787d56"): {common.BigToHash(big.NewInt(2038)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nyan-v2 18
	common.HexToAddress("0xbf4a9a37ecfc21825011285222c36ab35de51f14"): {common.BigToHash(big.NewInt(281800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//world-token 18
	common.HexToAddress("0xbf494f02ee3fde1f20bee6242bce2d1ed0c15e47"): {common.BigToHash(big.NewInt(157)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bnsd-finance 18
	common.HexToAddress("0x668DbF100635f593A3847c0bDaF21f0a09380188"): {common.BigToHash(big.NewInt(107)), common.BigToHash(big.NewInt(1000000000000000000))},
	//non-fungible-yearn 18
	common.HexToAddress("0x1cbb83ebcd552d5ebf8131ef8c9cd9d9bab342bc"): {common.BigToHash(big.NewInt(126400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wolfystreetbets 9
	common.HexToAddress("0x7dbbcae15d4db168e01673400d7844870cc1e36f"): {common.BigToHash(big.NewInt(13)), common.BigToHash(big.NewInt(1000000000))},
	//doyourtip 18
	common.HexToAddress("0x740623d2c797b7D8D1EcB98e9b4Afcf99Ec31E14"): {common.BigToHash(big.NewInt(2169)), common.BigToHash(big.NewInt(1000000000000000000))},
	//island-doges 9
	common.HexToAddress("0xa0dc5132c91ea4d94fcf1727c32cc5a303b34cfc"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//fetch 18
	common.HexToAddress("0xaea46A60368A7bD060eec7DF8CBa43b7EF41Ad85"): {common.BigToHash(big.NewInt(5068)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rogue-doge 9
	common.HexToAddress("0x45734927fa2f616fbe19e65f42a0ef3d37d1c80a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//polinate 18
	common.HexToAddress("0xa1a36d3537bbe375cc9694795f663ddc8d516db9"): {common.BigToHash(big.NewInt(105)), common.BigToHash(big.NewInt(1000000000000000000))},
	//edge 18
	common.HexToAddress("0x4ec1b60b96193a64acae44778e51f7bff2007831"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//floki-pup 9
	common.HexToAddress("0x259fba5ae8b626483e1e589e8d60a5413a2157d2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//wiva 18
	common.HexToAddress("0xa00055e6ee4d1f4169096ecb682f70caa8c29987"): {common.BigToHash(big.NewInt(497)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tycoon 18
	common.HexToAddress("0x3A82D3111aB5faF39d847D46023d9090261A658F"): {common.BigToHash(big.NewInt(390)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hotbit-token 18
	common.HexToAddress("0x6be61833fc4381990e82d7d4a9f4c9b3f67ea941"): {common.BigToHash(big.NewInt(446)), common.BigToHash(big.NewInt(1000000000000000000))},
	//playdapp 18
	common.HexToAddress("0x3a4f40631a4f906c2BaD353Ed06De7A5D3fCb430"): {common.BigToHash(big.NewInt(12183)), common.BigToHash(big.NewInt(1000000000000000000))},
	//auric-network 18
	common.HexToAddress("0x1c7bbadc81e18f7177a95eb1593e5f5f35861b10"): {common.BigToHash(big.NewInt(117)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xyo 18
	common.HexToAddress("0x55296f69f40ea6d20e478533c15a6b08b654e758"): {common.BigToHash(big.NewInt(296)), common.BigToHash(big.NewInt(1000000000000000000))},
	//murall 18
	common.HexToAddress("0x4c6ec08cf3fc987c6c4beb03184d335a2dfc4042"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//katalyo 18
	common.HexToAddress("0x24E3794605C84E580EEA4972738D633E8a7127c8"): {common.BigToHash(big.NewInt(914)), common.BigToHash(big.NewInt(1000000000000000000))},
	//solomon-defi 18
	common.HexToAddress("0x07a0ad7a9dfc3854466f8f29a173bf04bba5686e"): {common.BigToHash(big.NewInt(313)), common.BigToHash(big.NewInt(1000000000000000000))},
	//topbidder 18
	common.HexToAddress("0x00000000000045166c45af0fc6e4cf31d9e14b9a"): {common.BigToHash(big.NewInt(4954)), common.BigToHash(big.NewInt(1000000000000000000))},
	//women-empowerment-token 18
	common.HexToAddress("0x79E52C8D2cA6Ad34791899fCD19752A8bc51DEa5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//evolution-finance 18
	common.HexToAddress("0x9af15d7b8776fa296019979e70a5be53c714a7ec"): {common.BigToHash(big.NewInt(501453)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cryptokek 18
	common.HexToAddress("0x3fa400483487A489EC9b1dB29C4129063EEC4654"): {common.BigToHash(big.NewInt(334)), common.BigToHash(big.NewInt(1000000000000000000))},
	//balpha 18
	common.HexToAddress("0x7a5ce6abD131EA6B148a022CB76fc180ae3315A6"): {common.BigToHash(big.NewInt(222134)), common.BigToHash(big.NewInt(1000000000000000000))},
	//2crazynft 18
	common.HexToAddress("0x2c9c19ce3b15ae77c6d80aec3c1194cfd6f7f3fa"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pika 18
	common.HexToAddress("0x60F5672A271C7E39E787427A18353ba59A4A3578"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//spacechain 18
	common.HexToAddress("0x86ed939b500e121c0c5f493f399084db596dad20"): {common.BigToHash(big.NewInt(119)), common.BigToHash(big.NewInt(1000000000000000000))},
	//stater 18
	common.HexToAddress("0x84bb947fcedba6b9c7dcead42df07e113bb03007"): {common.BigToHash(big.NewInt(445)), common.BigToHash(big.NewInt(1000000000000000000))},
	//idle 18
	common.HexToAddress("0x875773784Af8135eA0ef43b5a374AaD105c5D39e"): {common.BigToHash(big.NewInt(17987)), common.BigToHash(big.NewInt(1000000000000000000))},
	//litentry 18
	common.HexToAddress("0xb59490ab09a0f526cc7305822ac65f2ab12f9723"): {common.BigToHash(big.NewInt(26100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//torn 18
	common.HexToAddress("0x77777feddddffc19ff86db637967013e6c6a116c"): {common.BigToHash(big.NewInt(300000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//spaceswap 18
	common.HexToAddress("0x80c8c3dcfb854f9542567c8dac3f44d709ebc1de"): {common.BigToHash(big.NewInt(1447)), common.BigToHash(big.NewInt(1000000000000000000))},
	//senator-karen 9
	common.HexToAddress("0x2881080650b782a48b03a1f5bd30df117b6a5bd5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//sentiment-token 18
	common.HexToAddress("0x97abee33cd075c58bfdd174e0885e08e8f03556f"): {common.BigToHash(big.NewInt(445)), common.BigToHash(big.NewInt(1000000000000000000))},
	//badger-dao 18
	common.HexToAddress("0x3472a5a71965499acd81997a54bba8d852c6e53d"): {common.BigToHash(big.NewInt(125317)), common.BigToHash(big.NewInt(1000000000000000000))},
	//peoples-punk 18
	common.HexToAddress("0x8ca9a0fbd8db501f013f2e9e33a1b9dc129a48e0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pinkslip-finance 18
	common.HexToAddress("0x36ce7a52cda404b8fa87a98d0d17ec7dd0b144ed"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//humans-ai 18
	common.HexToAddress("0x8FAc8031e079F409135766C7d5De29cf22EF897C"): {common.BigToHash(big.NewInt(1829)), common.BigToHash(big.NewInt(1000000000000000000))},
	//compound-dai 8
	common.HexToAddress("0x5d3a536e4d6dbd6114cc1ead35777bab948e3643"): {common.BigToHash(big.NewInt(221)), common.BigToHash(big.NewInt(100000000))},
	//arpa-chain 18
	common.HexToAddress("0xba50933c268f567bdc86e1ac131be072c6b0b71a"): {common.BigToHash(big.NewInt(875)), common.BigToHash(big.NewInt(1000000000000000000))},
	//luxfi 18
	common.HexToAddress("0xa799c4adcf62e025ce4d8abe6a77cebc487d772a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nms-token 18
	common.HexToAddress("0x77252494C25444F8598A0c74Ffc90ADc535291a9"): {common.BigToHash(big.NewInt(56)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unisocks 18
	common.HexToAddress("0x23b608675a2b2fb1890d3abbd85c5775c51691d5"): {common.BigToHash(big.NewInt(715300000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//softbtc 9
	common.HexToAddress("0x309013d55fb0e8c17363bcc79f25d92f711a5802"): {common.BigToHash(big.NewInt(191)), common.BigToHash(big.NewInt(1000000000))},
	//hypersign-identity 18
	common.HexToAddress("0xb14ebf566511b9e6002bb286016ab2497b9b9c9d"): {common.BigToHash(big.NewInt(901)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gamyfi-platform 18
	common.HexToAddress("0x65ad6a2288b2dd23e466226397c8f5d1794e58fc"): {common.BigToHash(big.NewInt(6835)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chow-inu 18
	common.HexToAddress("0x7ad8bc51c917076e5652954943cf0a9991e5a9f9"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yearn-finance-ii 18
	common.HexToAddress("0xa1d0E215a23d7030842FC67cE582a6aFa3CCaB83"): {common.BigToHash(big.NewInt(26459968)), common.BigToHash(big.NewInt(1000000000000000000))},
	//labs-group 18
	common.HexToAddress("0x8b0e42f366ba502d787bb134478adfae966c8798"): {common.BigToHash(big.NewInt(47)), common.BigToHash(big.NewInt(1000000000000000000))},
	//creator-platform 18
	common.HexToAddress("0x923b83c26B3809d960fF80332Ed00aA46D7Ed375"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xtoken 18
	common.HexToAddress("0x7f3edcdd180dbe4819bd98fee8929b5cedb3adeb"): {common.BigToHash(big.NewInt(299)), common.BigToHash(big.NewInt(1000000000000000000))},
	//solve 8
	common.HexToAddress("0x446c9033e7516d820cc9a2ce2d0b7328b579406f"): {common.BigToHash(big.NewInt(1120)), common.BigToHash(big.NewInt(100000000))},
	//kwikswap 18
	common.HexToAddress("0x286c0936c7eaf6651099ab5dab9ee5a6cb5d229d"): {common.BigToHash(big.NewInt(251)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mochi-inu 18
	common.HexToAddress("0x60ef10edff6d600cd91caeca04caed2a2e605fe5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wild-credit 18
	common.HexToAddress("0x08a75dbc7167714ceac1a8e43a8d643a4edd625a"): {common.BigToHash(big.NewInt(2342)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mini-saitama 9
	common.HexToAddress("0x0c3685559af6f3d20c501b1076a8056a0a14426a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//paypolitan-token 18
	common.HexToAddress("0x72630b1e3b42874bf335020ba0249e3e9e47bafc"): {common.BigToHash(big.NewInt(735)), common.BigToHash(big.NewInt(1000000000000000000))},
	//earthfund 18
	common.HexToAddress("0x9e04f519b094f5f8210441e285f603f4d2b50084"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//scaleswap 18
	common.HexToAddress("0x1FbD3dF007eB8A7477A1Eab2c63483dCc24EfFD6"): {common.BigToHash(big.NewInt(1637)), common.BigToHash(big.NewInt(1000000000000000000))},
	//communifty 18
	common.HexToAddress("0x8e2b4badac15a4ec8c56020f4ce60faa7558c052"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rougecoin 18
	common.HexToAddress("0xa1c7d450130bb77c6a23ddfaecbc4a060215384b"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kittenfinance 18
	common.HexToAddress("0x177ba0cac51bfc7ea24bad39d81dcefd59d74faa"): {common.BigToHash(big.NewInt(281867)), common.BigToHash(big.NewInt(1000000000000000000))},
	//society-of-galactic-exploration 9
	common.HexToAddress("0xab456bdb0a373bbac6c4a76176e9f159cacd5752"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//axia-protocol 18
	common.HexToAddress("0x793786e2dd4Cc492ed366a94B88a3Ff9ba5E7546"): {common.BigToHash(big.NewInt(3640)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dehive 18
	common.HexToAddress("0x62Dc4817588d53a056cBbD18231d91ffCcd34b2A"): {common.BigToHash(big.NewInt(5485)), common.BigToHash(big.NewInt(1000000000000000000))},
	//anatha 18
	common.HexToAddress("0x3383c5a8969Dc413bfdDc9656Eb80A1408E4bA20"): {common.BigToHash(big.NewInt(936)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hero-inu 9
	common.HexToAddress("0x97bFC1700bAF347659b525336B967AA375c05b01"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//satoru-inu 9
	common.HexToAddress("0xaf6f6abf18d2cc611921e6a683164efaa9165b43"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//daddybezos 9
	common.HexToAddress("0xbf825207c74b6c3c01ab807c4f4a4fce26ebdf0f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//1millionnfts 18
	common.HexToAddress("0xa4ef4b0b23c1fc81d3f9ecf93510e64f58a4a016"): {common.BigToHash(big.NewInt(7943)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shih-tzu 18
	common.HexToAddress("0x841fb148863454a3b3570f515414759be9091465"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//collateral-pay 18
	common.HexToAddress("0x957891c11616d3e0b0a76a76fb42724c382e0ef3"): {common.BigToHash(big.NewInt(765)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cryptonovae 18
	common.HexToAddress("0x4ee438be38f8682abb089f2bfea48851c5e71eaf"): {common.BigToHash(big.NewInt(610)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sav3token 18
	common.HexToAddress("0x6e10aacb89a28d6fa0fe68790777fec7e7f01890"): {common.BigToHash(big.NewInt(485)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shake 18
	common.HexToAddress("0x6006FC2a849fEdABa8330ce36F5133DE01F96189"): {common.BigToHash(big.NewInt(8265141)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nsure-network 18
	common.HexToAddress("0x20945cA1df56D237fD40036d47E866C7DcCD2114"): {common.BigToHash(big.NewInt(838)), common.BigToHash(big.NewInt(1000000000000000000))},
	//munch-token 9
	common.HexToAddress("0x944eee930933be5e23b690c8589021ec8619a301"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//demodyfi 18
	common.HexToAddress("0x5f6c5c2fb289db2228d159c69621215e354218d7"): {common.BigToHash(big.NewInt(867)), common.BigToHash(big.NewInt(1000000000000000000))},
	//soliditylabs 9
	common.HexToAddress("0x368dd0d9a2e595a7a617c3768cdb9a464e06ea69"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//ibeth 18
	common.HexToAddress("0x67B66C99D3Eb37Fa76Aa3Ed1ff33E8e39F0b9c7A"): {common.BigToHash(big.NewInt(34965209)), common.BigToHash(big.NewInt(1000000000000000000))},
	//froge-finance 9
	common.HexToAddress("0x29502fe4d233ef0b45c3647101fa1252ce0634bd"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//energy-ledger 18
	common.HexToAddress("0x9048c33c7bae0bbe9ad702b17b4453a83900d154"): {common.BigToHash(big.NewInt(133)), common.BigToHash(big.NewInt(1000000000000000000))},
	//coinburp 18
	common.HexToAddress("0x33f391f4c4fe802b70b77ae37670037a92114a7c"): {common.BigToHash(big.NewInt(483)), common.BigToHash(big.NewInt(1000000000000000000))},
	//boringdao-new 18
	common.HexToAddress("0xbc19712feb3a26080ebf6f2f7849b417fdd792ca"): {common.BigToHash(big.NewInt(420)), common.BigToHash(big.NewInt(1000000000000000000))},
	//digible 18
	common.HexToAddress("0x3CbF23c081fAA5419810ce0F6BC1ECb73006d848"): {common.BigToHash(big.NewInt(297)), common.BigToHash(big.NewInt(1000000000000000000))},
	//jarvis-network 18
	common.HexToAddress("0x8a9c67fee641579deba04928c4bc45f66e26343a"): {common.BigToHash(big.NewInt(833)), common.BigToHash(big.NewInt(1000000000000000000))},
	//atomic-wallet-coin 8
	common.HexToAddress("0xad22f63404f7305e4713ccbd4f296f34770513f4"): {common.BigToHash(big.NewInt(10430)), common.BigToHash(big.NewInt(100000000))},
	//blockchain-monster-hunt 18
	common.HexToAddress("0x2BA8349123de45E931a8C8264c332E6e9CF593F9"): {common.BigToHash(big.NewInt(10100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polkarare 18
	common.HexToAddress("0x2C2f7e7C5604D162d75641256b80F1Bf6f4dC796"): {common.BigToHash(big.NewInt(407)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yvault-lp-ycurve 18
	common.HexToAddress("0x5dbcF33D8c2E976c6b560249878e6F1491Bca25c"): {common.BigToHash(big.NewInt(12139)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bitbase-token 18
	common.HexToAddress("0x32e6c34cd57087abbd59b5a4aecc4cb495924356"): {common.BigToHash(big.NewInt(5217)), common.BigToHash(big.NewInt(1000000000000000000))},
	//non-fungible-toke 18
	common.HexToAddress("0x98ddc72bd02d448f68c4226f26122c66c5bd711e"): {common.BigToHash(big.NewInt(13)), common.BigToHash(big.NewInt(1000000000000000000))},
	//digital-reserve-currency 0
	common.HexToAddress("0xa150Db9b1Fa65b44799d4dD949D922c0a33Ee606"): {common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(1))},
	//centaur 18
	common.HexToAddress("0x03042482d64577a7bdb282260e2ea4c8a89c064b"): {common.BigToHash(big.NewInt(10)), common.BigToHash(big.NewInt(1000000000000000000))},
	//goji-crypto 12
	common.HexToAddress("0x72e5390edb7727e3d4e3436451dadaff675dbcc0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000))},
	//tranche-finance 18
	common.HexToAddress("0x0aee8703d34dd9ae107386d3eff22ae75dd616d1"): {common.BigToHash(big.NewInt(6115)), common.BigToHash(big.NewInt(1000000000000000000))},
	//relevant 18
	common.HexToAddress("0xb6c4267c4877bb0d6b1685cfd85b0fbe82f105ec"): {common.BigToHash(big.NewInt(6299)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kelvpn 18
	common.HexToAddress("0x4abb9cc67bd3da9eb966d1159a71a0e68bd15432"): {common.BigToHash(big.NewInt(65)), common.BigToHash(big.NewInt(1000000000000000000))},
	//equalizer 18
	common.HexToAddress("0x1Da87b114f35E1DC91F72bF57fc07A768Ad40Bb0"): {common.BigToHash(big.NewInt(1877)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cirus-foundation 18
	common.HexToAddress("0xa01199c61841fce3b3dafb83fefc1899715c8756"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dctdao 18
	common.HexToAddress("0xb566e883555aebf5b1db211070b530ab00a4b18a"): {common.BigToHash(big.NewInt(1180)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yup-token 18
	common.HexToAddress("0x69bBC3F8787d573F1BBDd0a5f40C7bA0Aee9BCC9"): {common.BigToHash(big.NewInt(5910)), common.BigToHash(big.NewInt(1000000000000000000))},
	//delta-theta 18
	common.HexToAddress("0x0000000de40dfa9b17854cbc7869d80f9f98d823"): {common.BigToHash(big.NewInt(665)), common.BigToHash(big.NewInt(1000000000000000000))},
	//open-governance-token 18
	common.HexToAddress("0x69e8b9528CABDA89fe846C67675B5D73d463a916"): {common.BigToHash(big.NewInt(857)), common.BigToHash(big.NewInt(1000000000000000000))},
	//juggernaut 18
	common.HexToAddress("0x73374ea518de7addd4c2b624c0e8b113955ee041"): {common.BigToHash(big.NewInt(4365)), common.BigToHash(big.NewInt(1000000000000000000))},
	//te-food 18
	common.HexToAddress("0x2ab6bb8408ca3199b8fa6c92d5b455f820af03c4"): {common.BigToHash(big.NewInt(225)), common.BigToHash(big.NewInt(1000000000000000000))},
	//doki-doki-finance 18
	common.HexToAddress("0x9ceb84f92a0561fa3cc4132ab9c0b76a59787544"): {common.BigToHash(big.NewInt(291975)), common.BigToHash(big.NewInt(1000000000000000000))},
	//imperial-obelisk 9
	common.HexToAddress("0x42a0d24cb5c423eaaf926ce3984aaff0c4ff6fe2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//keanu-inu 9
	common.HexToAddress("0x106552c11272420aad5d7e94f8acab9095a6c952"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//wallfair 18
	common.HexToAddress("0xC6065B9fc8171Ad3D29bad510709249681758972"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//vanilla-network 18
	common.HexToAddress("0xB97FaF860045483E0C7F08c56acb31333084a988"): {common.BigToHash(big.NewInt(54821)), common.BigToHash(big.NewInt(1000000000000000000))},
	//clintex-cti 18
	common.HexToAddress("0x8c18d6a985ef69744b9d57248a45c0861874f244"): {common.BigToHash(big.NewInt(428)), common.BigToHash(big.NewInt(1000000000000000000))},
	//connectico 18
	common.HexToAddress("0x40d2025ed2e89632d3a41d8541df9ed2ac0e2b1c"): {common.BigToHash(big.NewInt(1999)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defipie 18
	common.HexToAddress("0x607C794cDa77efB21F8848B7910ecf27451Ae842"): {common.BigToHash(big.NewInt(137)), common.BigToHash(big.NewInt(1000000000000000000))},
	//octofi 18
	common.HexToAddress("0x7240aC91f01233BaAf8b064248E80feaA5912BA3"): {common.BigToHash(big.NewInt(51914)), common.BigToHash(big.NewInt(1000000000000000000))},
	//base-protocol 9
	common.HexToAddress("0x07150e919b4de5fd6a63de1f9384828396f25fdc"): {common.BigToHash(big.NewInt(13783)), common.BigToHash(big.NewInt(1000000000))},
	//dsla-protocol 18
	common.HexToAddress("0x3affcca64c2a6f4e3b6bd9c64cd2c969efd1ecbe"): {common.BigToHash(big.NewInt(40)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nftfy 18
	common.HexToAddress("0xbf6ff49ffd3d104302ef0ab0f10f5a84324c091c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hoff-coin 8
	common.HexToAddress("0xb3f822dbbd694901e2051a2495a8755d6cfd5133"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100000000))},
	//jindoge 18
	common.HexToAddress("0x3f4cd830543db25254ec0f05eac058d4d6e86166"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hakka-finance 18
	common.HexToAddress("0x0e29e5abbb5fd88e28b2d355774e73bd47de3bcd"): {common.BigToHash(big.NewInt(161)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mm-token 18
	common.HexToAddress("0xa283aa7cfbb27ef0cfbcb2493dd9f4330e0fd304"): {common.BigToHash(big.NewInt(18100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//salt 8
	common.HexToAddress("0x4156D3342D5c385a87D264F90653733592000581"): {common.BigToHash(big.NewInt(1052)), common.BigToHash(big.NewInt(100000000))},
	//status 18
	common.HexToAddress("0x744d70fdbe2ba4cf95131626614a1763df805b9e"): {common.BigToHash(big.NewInt(635)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hina-inu 9
	common.HexToAddress("0xbd0a4bf098261673d5e6e600fd87ddcd756e6764"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//kakashiinuv2 9
	common.HexToAddress("0x15a6d1392188cc1fc1d99936e7d3c09e28c21465"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//moar-finance 18
	common.HexToAddress("0x187eff9690e1f1a61d578c7c492296eaab82701a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//morpher 18
	common.HexToAddress("0x6369c3dadfc00054a42ba8b2c09c48131dd4aa38"): {common.BigToHash(big.NewInt(230)), common.BigToHash(big.NewInt(1000000000000000000))},
	//moontools 18
	common.HexToAddress("0x260e63d91fCCC499606BAe3FE945c4ed1CF56A56"): {common.BigToHash(big.NewInt(141264)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fat-doge 9
	common.HexToAddress("0x76851a93977bea9264c32255b6457882035c7501"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//ethbox 18
	common.HexToAddress("0x33840024177a7daca3468912363bed8b425015c5"): {common.BigToHash(big.NewInt(357)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polkainsure-finance 18
	common.HexToAddress("0x834ce7ad163ab3be0c5fd4e0a81e67ac8f51e00c"): {common.BigToHash(big.NewInt(65600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//definity 18
	common.HexToAddress("0x5F474906637bdCDA05f29C74653F6962bb0f8eDa"): {common.BigToHash(big.NewInt(278)), common.BigToHash(big.NewInt(1000000000000000000))},
	//iconic-token 18
	common.HexToAddress("0xb3e2cb7cccfe139f8ff84013823bf22da6b6390a"): {common.BigToHash(big.NewInt(3733)), common.BigToHash(big.NewInt(1000000000000000000))},
	//derivadao 18
	common.HexToAddress("0x3a880652f47bfaa771908c07dd8673a787daed3a"): {common.BigToHash(big.NewInt(39200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cometh 18
	common.HexToAddress("0x9c78ee466d6cb57a4d01fd887d2b5dfb2d46288f"): {common.BigToHash(big.NewInt(659000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//truefi-token 8
	common.HexToAddress("0x4c19596f5aaff459fa38b0f7ed92f11ae6543784"): {common.BigToHash(big.NewInt(2703)), common.BigToHash(big.NewInt(100000000))},
	//xsigma 18
	common.HexToAddress("0x7777777777697cfeecf846a76326da79cc606517"): {common.BigToHash(big.NewInt(918)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polkapets 18
	common.HexToAddress("0x6afcff9189e8ed3fcc1cffa184feb1276f6a82a5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pupper 18
	common.HexToAddress("0x81dBc1c8e40C3095071949Eda9800C2209a7279A"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//metarcade 18
	common.HexToAddress("0xb120b0b309f6ee56b67a7a6af216ab2fe56c3ed2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lympo 18
	common.HexToAddress("0xc690f7c7fcffa6a82b79fab7508c466fefdfc8c5"): {common.BigToHash(big.NewInt(85)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nft-tech 18
	common.HexToAddress("0x5fA2E9Ba5757504B3d6e8f6da03cc40d4ce19499"): {common.BigToHash(big.NewInt(651)), common.BigToHash(big.NewInt(1000000000000000000))},
	//smartcredit-token 18
	common.HexToAddress("0x72e9d9038ce484ee986fea183f8d8df93f9ada13"): {common.BigToHash(big.NewInt(21676)), common.BigToHash(big.NewInt(1000000000000000000))},
	//keisuke-inu 9
	common.HexToAddress("0xc0114f14638a333a4d5c3b04f09b96372348a842"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//pundix-new 18
	common.HexToAddress("0xa15c7ebe1f07caf6bff097d8a589fb8ac49ae5b3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dragonbite 18
	common.HexToAddress("0x4eed0fa8de12d5a86517f214c2f11586ba2ed88d"): {common.BigToHash(big.NewInt(18)), common.BigToHash(big.NewInt(1000000000000000000))},
	//meta-shiba 18
	common.HexToAddress("0x9cF77be84214beb066F26a4ea1c38ddcc2AFbcf7"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bnktothefuture 18
	common.HexToAddress("0x01ff50f8b7f74e4f00580d9596cd3d0d6d6e326f"): {common.BigToHash(big.NewInt(112)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shinjutsu 9
	common.HexToAddress("0x6e6c6b24371d2ee18fc39b4bc534b4344d2bbd61"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//blockv 18
	common.HexToAddress("0x340d2bde5eb28c1eed91b2f790723e3b160613b7"): {common.BigToHash(big.NewInt(78)), common.BigToHash(big.NewInt(1000000000000000000))},
	//hayate-inu 18
	common.HexToAddress("0x903aed40b7fcbe8de84a699151c9055f4c0a6db3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//axioms 18
	common.HexToAddress("0x73ee6d7e6b203125add89320e9f343d65ec7c39a"): {common.BigToHash(big.NewInt(343)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bittoken 18
	common.HexToAddress("0x9f9913853f749b3fe6d6d4e16a1cc3c1656b6d51"): {common.BigToHash(big.NewInt(1049)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chopper-inu 9
	common.HexToAddress("0x28c5805b64d163588a909012a628b5a03c1041f9"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//unreal-finance 18
	common.HexToAddress("0x9cf98eb8a8b28c83e8612046cf55701ce3eb0063"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//multiplier 8
	common.HexToAddress("0x8a6f3bf52a26a21531514e23016eeae8ba7e7018"): {common.BigToHash(big.NewInt(80)), common.BigToHash(big.NewInt(100000000))},
	//governor-dao 18
	common.HexToAddress("0x515d7e9d75e2b76db60f8a051cd890eba23286bc"): {common.BigToHash(big.NewInt(7691)), common.BigToHash(big.NewInt(1000000000000000000))},
	//crypto-excellence 18
	common.HexToAddress("0x8f12dfc7981de79a8a34070a732471f2d335eece"): {common.BigToHash(big.NewInt(40100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//statera 18
	common.HexToAddress("0xa7DE087329BFcda5639247F96140f9DAbe3DeED1"): {common.BigToHash(big.NewInt(291)), common.BigToHash(big.NewInt(1000000000000000000))},
	//prostarter 18
	common.HexToAddress("0x2341dd0a96a0dab62aa1efb93d59ff7f3bdb8932"): {common.BigToHash(big.NewInt(528)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sewer-rat-social-club-chiz-token 18
	common.HexToAddress("0x5c761c1a21637362374204000e383204d347064c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//parachute 18
	common.HexToAddress("0x1beef31946fbbb40b877a72e4ae04a8d1a5cee06"): {common.BigToHash(big.NewInt(22)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cash-tech 18
	common.HexToAddress("0xa42f266684ac2ad6ecb00df95b1c76efbb6f136c"): {common.BigToHash(big.NewInt(44)), common.BigToHash(big.NewInt(1000000000000000000))},
	//safe-shield 9
	common.HexToAddress("0x11a605d7e12b64d713e93c487277d819a1d14b99"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//hedget 6
	common.HexToAddress("0x7968bc6a03017ea2de509aaa816f163db0f35148"): {common.BigToHash(big.NewInt(24600)), common.BigToHash(big.NewInt(1000000))},
	//piedao-dough-v2 18
	common.HexToAddress("0xad32A8e6220741182940c5aBF610bDE99E737b2D"): {common.BigToHash(big.NewInt(3549)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sync-network 18
	common.HexToAddress("0xb6ff96b8a8d214544ca0dbc9b33f7ad6503efd32"): {common.BigToHash(big.NewInt(123)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bitgear 18
	common.HexToAddress("0x1b980e05943dE3dB3a459C72325338d327B6F5a9"): {common.BigToHash(big.NewInt(149)), common.BigToHash(big.NewInt(1000000000000000000))},
	//earnbase 18
	common.HexToAddress("0xa6fb1df483b24eeab569e19447e0e107003b9e15"): {common.BigToHash(big.NewInt(10743)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mysterium 18
	common.HexToAddress("0x4Cf89ca06ad997bC732Dc876ed2A7F26a9E7f361"): {common.BigToHash(big.NewInt(4351)), common.BigToHash(big.NewInt(1000000000000000000))},
	//infinity-pad 18
	common.HexToAddress("0x36ed7baad9a571b5dad55d096c0ed902188d6d3c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//liti-capital 18
	common.HexToAddress("0x0b63128c40737b13647552e0c926bcfeccc35f93"): {common.BigToHash(big.NewInt(86)), common.BigToHash(big.NewInt(1000000000000000000))},
	//quantstamp 18
	common.HexToAddress("0x99ea4db9ee77acd40b119bd1dc4e33e1c070b80d"): {common.BigToHash(big.NewInt(350)), common.BigToHash(big.NewInt(1000000000000000000))},
	//renascent-finance 18
	common.HexToAddress("0x56de8bc61346321d4f2211e3ac3c0a7f00db9b76"): {common.BigToHash(big.NewInt(4557)), common.BigToHash(big.NewInt(1000000000000000000))},
	//evidenz 18
	common.HexToAddress("0xacfa209fb73bf3dd5bbfb1101b9bc999c49062a5"): {common.BigToHash(big.NewInt(1414)), common.BigToHash(big.NewInt(1000000000000000000))},
	//degen-arts 18
	common.HexToAddress("0x8281ee37f164c0e26e6b6f87e7695baac256df07"): {common.BigToHash(big.NewInt(39500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//american-shiba 9
	common.HexToAddress("0xb893a8049f250b57efa8c62d51527a22404d7c9a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//finminity 18
	common.HexToAddress("0x99c6e435eC259A7E8d65E1955C9423DB624bA54C"): {common.BigToHash(big.NewInt(1030)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rogue-west 8
	common.HexToAddress("0x6ac665c0de9a6ca72b85757b141aa9c428828aca"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100000000))},
	//electric-vehicle-direct-currency 18
	common.HexToAddress("0x704eae6d452ca63ce479c59727177c5f3ba0d90c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ydragon 18
	common.HexToAddress("0x3757232b55e60da4a8793183ac030cfce4c3865d"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wolves-of-wall-street 18
	common.HexToAddress("0x672EF7E4Fe230B5cA1466C5fDD40588d30FdF90a"): {common.BigToHash(big.NewInt(316000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//labracoin 9
	common.HexToAddress("0x106d3c66d22d2dd0446df23d7f5960752994d600"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//int-chain 18
	common.HexToAddress("0xbe038a2fdfec62cf1bed852f141a43005035edcc"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//follow-token 18
	common.HexToAddress("0xb2a63a5dd36c91ec2da59b188ff047f66fac122a"): {common.BigToHash(big.NewInt(140)), common.BigToHash(big.NewInt(1000000000000000000))},
	//phoenixdao 18
	common.HexToAddress("0x38A2fDc11f526Ddd5a607C1F251C065f40fBF2f7"): {common.BigToHash(big.NewInt(446)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chihua-token 18
	common.HexToAddress("0x26ff6d16549a00ba8b36ce3159b5277e6e798d18"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tails 9
	common.HexToAddress("0x3d79abb948bc76794ff4a0bcd60170a741f26360"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//spherium 18
	common.HexToAddress("0x8a0cdfab62ed35b836dc0633482798421c81b3ec"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cxn-network 18
	common.HexToAddress("0xb48E0F69e6A3064f5498D495F77AD83e0874ab28"): {common.BigToHash(big.NewInt(10)), common.BigToHash(big.NewInt(1000000000000000000))},
	//power-ledger 6
	common.HexToAddress("0x595832f8fc6bf59c85c527fec3740a1b7a361269"): {common.BigToHash(big.NewInt(5340)), common.BigToHash(big.NewInt(1000000))},
	//bartertrade 18
	common.HexToAddress("0x54c9ea2e9c9e8ed865db4a4ce6711c2a0d5063ba"): {common.BigToHash(big.NewInt(38)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unicat 9
	common.HexToAddress("0x87c0192b1b81b9550d495558aac9753972f6db0d"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//shibaken-finance 0
	common.HexToAddress("0xa4cf2afd3b165975afffbf7e487cdd40c894ab6b"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1))},
	//meme-inu 18
	common.HexToAddress("0x74b988156925937bd4e082f0ed7429da8eaea8db"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//justbet 18
	common.HexToAddress("0x27460aac4b005de72e2326bd8391c27fb41780f8"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//vox-finance 18
	common.HexToAddress("0x12D102F06da35cC0111EB58017fd2Cd28537d0e1"): {common.BigToHash(big.NewInt(98005)), common.BigToHash(big.NewInt(1000000000000000000))},
	//whiteheart 18
	common.HexToAddress("0x5f0e628b693018f639d10e4a4f59bd4d8b2b6b44"): {common.BigToHash(big.NewInt(4119500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//swarm-network 18
	common.HexToAddress("0x3505f494c3f0fed0b594e01fa41dd3967645ca39"): {common.BigToHash(big.NewInt(167)), common.BigToHash(big.NewInt(1000000000000000000))},
	//acoconut 18
	common.HexToAddress("0x9A0aBA393aac4dFbFf4333B06c407458002C6183"): {common.BigToHash(big.NewInt(1759)), common.BigToHash(big.NewInt(1000000000000000000))},
	//swftcoin 8
	common.HexToAddress("0x0bb217E40F8a5Cb79Adf04E1aAb60E5abd0dfC1e"): {common.BigToHash(big.NewInt(15)), common.BigToHash(big.NewInt(100000000))},
	//davincij15-token 9
	common.HexToAddress("0x5d269fac3b2e0552b0f34cdc253bdb427682a4b9"): {common.BigToHash(big.NewInt(1149728)), common.BigToHash(big.NewInt(1000000000))},
	//baby-floki-doge 9
	common.HexToAddress("0x747c4ce9622ea750ea8048423b38a746b096c8e8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//coshi-inu 9
	common.HexToAddress("0x668c50b1c7f46effbe3f242687071d7908aab00a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//nft-stars 18
	common.HexToAddress("0x08037036451c768465369431da5c671ad9b37dbc"): {common.BigToHash(big.NewInt(5988)), common.BigToHash(big.NewInt(1000000000000000000))},
	//money-party 6
	common.HexToAddress("0x314bd765cab4774b2e547eb0aa15013e03ff74d2"): {common.BigToHash(big.NewInt(11)), common.BigToHash(big.NewInt(1000000))},
	//first-eleven 18
	common.HexToAddress("0x309c1b3282c49E4dC6796644417f8c76b7C8233C"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//jomon-shiba 9
	common.HexToAddress("0x1426cC6D52D1B14e2B3b1Cb04d57ea42B39c4c7c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//lelouch-lamperouge 9
	common.HexToAddress("0x4546d782ffb14a465a3bb518eecf1a181da85332"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//yfox-finance 6
	common.HexToAddress("0x706CB9E741CBFee00Ad5b3f5ACc8bd44D1644a74"): {common.BigToHash(big.NewInt(158001)), common.BigToHash(big.NewInt(1000000))},
	//nft-wars 18
	common.HexToAddress("0x4d75D9e37667a2d4677Ec3d74bDD9049326Ad8d6"): {common.BigToHash(big.NewInt(1916)), common.BigToHash(big.NewInt(1000000000000000000))},
	//scifi-finance 18
	common.HexToAddress("0x1fdab294eda5112b7d066ed8f2e4e562d5bcc664"): {common.BigToHash(big.NewInt(1713)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mars 18
	common.HexToAddress("0x66C0DDEd8433c9EA86C8cf91237B14e10b4d70B7"): {common.BigToHash(big.NewInt(57)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kimchi-finance 18
	common.HexToAddress("0x1e18821e69b9faa8e6e75dffe54e7e25754beda0"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dao1 18
	common.HexToAddress("0xce3f6f6672616c39d8b6858f8dac9902eca42c84"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mozik 18
	common.HexToAddress("0x7BD82B320EbC28D8EB3C4F5Fa2af7B14dA5b90C3"): {common.BigToHash(big.NewInt(30)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pink-panther 18
	common.HexToAddress("0xa113b79c09f0794568b8864a24197e0b817041ea"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//combine-finance 18
	common.HexToAddress("0x7d36cce46dd2b0d28dde12a859c2ace4a21e3678"): {common.BigToHash(big.NewInt(366284)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kangal 18
	common.HexToAddress("0x6e765d26388a17a6e86c49a8e41df3f58abcd337"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//low-orbit-crypto-cannon 18
	common.HexToAddress("0x556938621C19e5eae58C94a806da9d237b969bd8"): {common.BigToHash(big.NewInt(3768639)), common.BigToHash(big.NewInt(1000000000000000000))},
	//megashibox-inu 18
	common.HexToAddress("0x0441890a456a61098fe1ee4082c2006a2c2b9330"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//froggies 9
	common.HexToAddress("0x7c3ff33c76c919b3f5fddaf7bdddbb20a826dc61"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//small-dogecoin 18
	common.HexToAddress("0x537edd52ebcb9f48ff2f8a28c51fcdb9d6a6e0d4"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//deflect 9
	common.HexToAddress("0x3aa5f749d4a6bcf67dac1091ceb69d1f5d86fa53"): {common.BigToHash(big.NewInt(16600)), common.BigToHash(big.NewInt(1000000000))},
	//bankroll-vault 18
	common.HexToAddress("0x6b785a0322126826d8226d77e173d75dafb84d11"): {common.BigToHash(big.NewInt(2980)), common.BigToHash(big.NewInt(1000000000000000000))},
	//floki-adventure 9
	common.HexToAddress("0x8b23b79ea039cf7242a91f2e3ef88df6f565d1ff"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//cryptotwitter 9
	common.HexToAddress("0x2e9cce8c3bf731f9bfc39e3d345a70907f454d40"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//king-arthur 9
	common.HexToAddress("0x1ca02dd95f3f1e33da7f5afe15ea866dab07af04"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//elonspets 18
	common.HexToAddress("0x40b50a516e081945b95d30fcbbb31476a63ffb4a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//stakerdao 18
	common.HexToAddress("0x89dcff5fd892f2bfc8b75dba12804b651f769579"): {common.BigToHash(big.NewInt(153)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ledgerscore 18
	common.HexToAddress("0x72De803b67B6AB05B61EFab2Efdcd414D16eBF6D"): {common.BigToHash(big.NewInt(91)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mochi-market 18
	common.HexToAddress("0xbd1848e1491d4308ad18287a745dd4db2a4bd55b"): {common.BigToHash(big.NewInt(558)), common.BigToHash(big.NewInt(1000000000000000000))},
	//aloha 18
	common.HexToAddress("0x455f7ef6d8bcfc35f9337e85aee1b0600a59fabe"): {common.BigToHash(big.NewInt(119)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defiplaza 18
	common.HexToAddress("0x2F57430a6ceDA85a67121757785877b4a71b8E6D"): {common.BigToHash(big.NewInt(936)), common.BigToHash(big.NewInt(1000000000000000000))},
	//font 18
	common.HexToAddress("0x4c25bdf026ea05f32713f00f73ca55857fbf6342"): {common.BigToHash(big.NewInt(10900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cryptotask 18
	common.HexToAddress("0x196c81385bc536467433014042788eb707703934"): {common.BigToHash(big.NewInt(2574)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kimetsu-inu 9
	common.HexToAddress("0x91e8d1b5f386204a82e6de32d4bae11d0b042f0f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//just-ape 9
	common.HexToAddress("0x40e0a6ef9dbadfc83c5e0d15262feb4638588d77"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//peerex 18
	common.HexToAddress("0x3c6ff50c9ec362efa359317009428d52115fe643"): {common.BigToHash(big.NewInt(8)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lunafox 9
	common.HexToAddress("0x0924d87605e51764a4620b8c41712a29e9c234c9"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//onooks 18
	common.HexToAddress("0x69d9905b2e5f6f5433212b7f3c954433f23c1572"): {common.BigToHash(big.NewInt(11472)), common.BigToHash(big.NewInt(1000000000000000000))},
	//zero-utility-token 18
	common.HexToAddress("0x83F873388Cd14b83A9f47FabDe3C9850b5C74548"): {common.BigToHash(big.NewInt(3132100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//suni 18
	common.HexToAddress("0x4a22a69e45ab29f9f7276b0267797474daf1f27c"): {common.BigToHash(big.NewInt(43)), common.BigToHash(big.NewInt(1000000000000000000))},
	//n-word-pass 18
	common.HexToAddress("0x28b1c08335fc02a82cbf7af850b01b01b9dc34e6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dimitra-token 18
	common.HexToAddress("0x51cB253744189f11241becb29BeDd3F1b5384fdB"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dether 18
	common.HexToAddress("0x5adc961d6ac3f7062d2ea45fefb8d8167d44b190"): {common.BigToHash(big.NewInt(33)), common.BigToHash(big.NewInt(1000000000000000000))},
	//monolith 8
	common.HexToAddress("0xaaaf91d9b90df800df4f55c205fd6989c977e73a"): {common.BigToHash(big.NewInt(2000)), common.BigToHash(big.NewInt(100000000))},
	//rain-network 18
	common.HexToAddress("0x61cdb66e56fad942a7b5ce3f419ffe9375e31075"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unidollar 18
	common.HexToAddress("0x256845e721c0c46d54e6afbd4fa3b52cb72353ea"): {common.BigToHash(big.NewInt(13)), common.BigToHash(big.NewInt(1000000000000000000))},
	//antiscamtoken 18
	common.HexToAddress("0xa872e0a44bbd66c1486a756cb5bd3f0beec4e32e"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kids-cash 18
	common.HexToAddress("0x2c50ba1ed5e4574c1b613b044bd1876f0b0b87a9"): {common.BigToHash(big.NewInt(1127)), common.BigToHash(big.NewInt(1000000000000000000))},
	//orchid 18
	common.HexToAddress("0x4575f41308EC1483f3d399aa9a2826d74Da13Deb"): {common.BigToHash(big.NewInt(3267)), common.BigToHash(big.NewInt(1000000000000000000))},
	//trustdao 18
	common.HexToAddress("0x57700244B20f84799a31c6C96DadFF373ca9D6c5"): {common.BigToHash(big.NewInt(52)), common.BigToHash(big.NewInt(1000000000000000000))},
	//aludra-network 18
	common.HexToAddress("0xb339FcA531367067e98d7c4f9303Ffeadff7B881"): {common.BigToHash(big.NewInt(9)), common.BigToHash(big.NewInt(1000000000000000000))},
	//libera 18
	common.HexToAddress("0x0bf6261297198d91d4fa460242c69232146a5703"): {common.BigToHash(big.NewInt(11200)), common.BigToHash(big.NewInt(1000000000000000000))},
	//meridian-network 18
	common.HexToAddress("0x95172ccBe8344fecD73D0a30F54123652981BD6F"): {common.BigToHash(big.NewInt(147)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defi-bids 18
	common.HexToAddress("0x1dA01e84F3d4e6716F274c987Ae4bEE5DC3C8288"): {common.BigToHash(big.NewInt(104)), common.BigToHash(big.NewInt(1000000000000000000))},
	//keysians-network 18
	common.HexToAddress("0x6a7ef4998eb9d0f706238756949f311a59e05745"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yield-stake-finance 18
	common.HexToAddress("0x03e4bdce611104289333f35c8177558b04cc99ff"): {common.BigToHash(big.NewInt(67106)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xiotri 3
	common.HexToAddress("0x31024a4c3e9aeeb256b825790f5cb7ac645e7cd5"): {common.BigToHash(big.NewInt(964016)), common.BigToHash(big.NewInt(1000))},
	//lien 8
	common.HexToAddress("0xab37e1358b639fd877f015027bb62d3ddaa7557e"): {common.BigToHash(big.NewInt(13000)), common.BigToHash(big.NewInt(100000000))},
	//walnut-finance 18
	common.HexToAddress("0x0501e7a02c285b9b520fdbf1badc74ae931ad75d"): {common.BigToHash(big.NewInt(10887)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bitto 18
	common.HexToAddress("0x55a290f08bb4cae8dcf1ea5635a3fcfd4da60456"): {common.BigToHash(big.NewInt(959)), common.BigToHash(big.NewInt(1000000000000000000))},
	//satopay-network 18
	common.HexToAddress("0x8c3ee4f778e282b59d42d693a97b80b1ed80f4ee"): {common.BigToHash(big.NewInt(13)), common.BigToHash(big.NewInt(1000000000000000000))},
	//swapfolio 18
	common.HexToAddress("0xba21ef4c9f433ede00badefcc2754b8e74bd538a"): {common.BigToHash(big.NewInt(874)), common.BigToHash(big.NewInt(1000000000000000000))},
	//seigniorage-shares 9
	common.HexToAddress("0x39795344CBCc76cC3Fb94B9D1b15C23c2070C66D"): {common.BigToHash(big.NewInt(159)), common.BigToHash(big.NewInt(1000000000))},
	//yfbeta 18
	common.HexToAddress("0x89ee58af4871b474c30001982c3d7439c933c838"): {common.BigToHash(big.NewInt(93297)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defiat 18
	common.HexToAddress("0xb6ee603933e024d8d53dde3faa0bf98fe2a3d6f1"): {common.BigToHash(big.NewInt(2397)), common.BigToHash(big.NewInt(1000000000000000000))},
	//geodb 18
	common.HexToAddress("0x147faf8de9d8d8daae129b187f0d02d819126750"): {common.BigToHash(big.NewInt(218)), common.BigToHash(big.NewInt(1000000000000000000))},
	//coin-artist 18
	common.HexToAddress("0x87b008E57F640D94Ee44Fd893F0323AF933F9195"): {common.BigToHash(big.NewInt(9039)), common.BigToHash(big.NewInt(1000000000000000000))},
	//the-forms 18
	common.HexToAddress("0x8b80596660f007342dc590e5c53bbddd2cd550fb"): {common.BigToHash(big.NewInt(67)), common.BigToHash(big.NewInt(1000000000000000000))},
	//foresight 18
	common.HexToAddress("0xb1EC548F296270BC96B8A1b3b3C8F3f04b494215"): {common.BigToHash(big.NewInt(318)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lead-wallet 18
	common.HexToAddress("0x1dd80016e3d4ae146ee2ebb484e8edd92dacc4ce"): {common.BigToHash(big.NewInt(37)), common.BigToHash(big.NewInt(1000000000000000000))},
	//blockclout 18
	common.HexToAddress("0xa10ae543db5d967a73e9abcc69c81a18a7fc0a78"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fireball 18
	common.HexToAddress("0x3F8A2f7bcD70e7F7Bdd3FbB079c11d073588DEA2"): {common.BigToHash(big.NewInt(300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//aga 4
	common.HexToAddress("0x2d80f5f5328fdcb6eceb7cacf5dd8aedaec94e20"): {common.BigToHash(big.NewInt(2455)), common.BigToHash(big.NewInt(10000))},
	//waifu-token 18
	common.HexToAddress("0xb2279b6769cfba691416f00609b16244c0cf4b20"): {common.BigToHash(big.NewInt(10)), common.BigToHash(big.NewInt(1000000000000000000))},
	//equus-mining-token 18
	common.HexToAddress("0xa462d0E6Bb788c7807B1B1C96992CE1f7069E195"): {common.BigToHash(big.NewInt(16)), common.BigToHash(big.NewInt(1000000000000000000))},
	//myx-network 18
	common.HexToAddress("0x2129fF6000b95A973236020BCd2b2006B0D8E019"): {common.BigToHash(big.NewInt(15)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lync-network 18
	common.HexToAddress("0x8f87Ec6aAd3B2A8C44f1298A1af56169B8e574cf"): {common.BigToHash(big.NewInt(4626)), common.BigToHash(big.NewInt(1000000000000000000))},
	//decraft-finance 18
	common.HexToAddress("0xa09ff006c652496e72d648cef2f4ee6777efdf6f"): {common.BigToHash(big.NewInt(385232)), common.BigToHash(big.NewInt(1000000000000000000))},
	//insights-network 4
	common.HexToAddress("0x8193711b2763bc7dfd67da0d6c8c26642eafdaf3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(10000))},
	//yrise-finance 18
	common.HexToAddress("0x6051C1354Ccc51b4d561e43b02735DEaE64768B8"): {common.BigToHash(big.NewInt(16000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fera 18
	common.HexToAddress("0x539f3615c1dbafa0d008d87504667458acbd16fa"): {common.BigToHash(big.NewInt(46)), common.BigToHash(big.NewInt(1000000000000000000))},
	//degenvc 18
	common.HexToAddress("0x26E43759551333e57F073bb0772F50329A957b30"): {common.BigToHash(big.NewInt(3810)), common.BigToHash(big.NewInt(1000000000000000000))},
	//zoom-protocol 18
	common.HexToAddress("0x1a231e75538a931c395785ef5d1a5581ec622b0e"): {common.BigToHash(big.NewInt(67340)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bananodos 18
	common.HexToAddress("0x1706c33B9a5B12aeB85B862215378dEe9480EB95"): {common.BigToHash(big.NewInt(1491517)), common.BigToHash(big.NewInt(1000000000000000000))},
	//coil 9
	common.HexToAddress("0x3936ad01cf109a36489d93cabda11cf062fd3d48"): {common.BigToHash(big.NewInt(9958)), common.BigToHash(big.NewInt(1000000000))},
	//xfinance 18
	common.HexToAddress("0x5BEfBB272290dD5b8521D4a938f6c4757742c430"): {common.BigToHash(big.NewInt(720699)), common.BigToHash(big.NewInt(1000000000000000000))},
	//swag-finance 18
	common.HexToAddress("0x87edffde3e14c7a66c9b9724747a1c5696b742e6"): {common.BigToHash(big.NewInt(177)), common.BigToHash(big.NewInt(1000000000000000000))},
	//finswap 18
	common.HexToAddress("0x3B78dc5736a49BD297Dd2E4d62daA83D35A22749"): {common.BigToHash(big.NewInt(1095)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yfe-money 18
	common.HexToAddress("0x33811d4edbcaed10a685254eb5d3c4e4398520d2"): {common.BigToHash(big.NewInt(37800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chads-vc 18
	common.HexToAddress("0x69692D3345010a207b759a7D1af6fc7F38b35c5E"): {common.BigToHash(big.NewInt(501)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bellevue-network 18
	common.HexToAddress("0x8DA25B8eD753a5910013167945A676921e864436"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yfpro-finance 18
	common.HexToAddress("0x0fdc5313333533cc0c00c22792bff7383d3055f2"): {common.BigToHash(big.NewInt(36835)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tsunami 18
	common.HexToAddress("0x7eb4db4dddb16a329c5ade17a8a0178331267e28"): {common.BigToHash(big.NewInt(1177811)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yeld-finance 18
	common.HexToAddress("0x468ab3b1f63A1C14b361bC367c3cC92277588Da1"): {common.BigToHash(big.NewInt(47938)), common.BigToHash(big.NewInt(1000000000000000000))},
	//upbots 18
	common.HexToAddress("0x8564653879a18C560E7C0Ea0E084c516C62F5653"): {common.BigToHash(big.NewInt(224)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ofin-token 18
	common.HexToAddress("0x3b4cAAAF6F3ce5Bee2871C89987cbd825Ac30822"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tribute 18
	common.HexToAddress("0x7031ab87dcc46818806ec07af46fa8c2ad2a2bfc"): {common.BigToHash(big.NewInt(4556)), common.BigToHash(big.NewInt(1000000000000000000))},
	//momentum 10
	common.HexToAddress("0x9a7a4c141a3bcce4a31e42c1192ac6add35069b4"): {common.BigToHash(big.NewInt(13)), common.BigToHash(big.NewInt(10000000000))},
	//ytsla-finance 18
	common.HexToAddress("0x5322a3556f979ce2180b30e689a9436fddcb1021"): {common.BigToHash(big.NewInt(104465)), common.BigToHash(big.NewInt(1000000000000000000))},
	//payship 18
	common.HexToAddress("0x88D59Ba796fDf639dEd3b5E720988D59fDb71Eb8"): {common.BigToHash(big.NewInt(318600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//swapship 18
	common.HexToAddress("0x3ac2AB91dDF57e2385089202Ca221C360CED0062"): {common.BigToHash(big.NewInt(46426)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shill-win 18
	common.HexToAddress("0x685aea4F02E39E5a5BB7f7117E88DB1151F38364"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wrapped-leo 3
	common.HexToAddress("0x73a9fb46e228628f8f9bb9004eca4f4f529d3998"): {common.BigToHash(big.NewInt(2092)), common.BigToHash(big.NewInt(1000))},
	//owl-token-stealthswap 18
	common.HexToAddress("0x2a7f709ee001069771ceb6d42e85035f7d18e736"): {common.BigToHash(big.NewInt(1519)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dracula-token 18
	common.HexToAddress("0xb78B3320493a4EFaa1028130C5Ba26f0B6085Ef8"): {common.BigToHash(big.NewInt(302)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tomochain 18
	common.HexToAddress("0x05d3606d5c81eb9b7b18530995ec9b29da05faba"): {common.BigToHash(big.NewInt(16503)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yearn-finance-ecosystem 8
	common.HexToAddress("0x2e6e152d29053b6337e434bc9be17504170f8a5b"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100000000))},
	//quiverx 18
	common.HexToAddress("0x6e0dade58d2d89ebbe7afc384e3e4f15b70b14d8"): {common.BigToHash(big.NewInt(170)), common.BigToHash(big.NewInt(1000000000000000000))},
	//moonday-finance 18
	common.HexToAddress("0x1ad606adde97c0c28bd6ac85554176bc55783c01"): {common.BigToHash(big.NewInt(874400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chonk 18
	common.HexToAddress("0x84679bc467DC6c2c40ab04538813AfF3796351f1"): {common.BigToHash(big.NewInt(211624)), common.BigToHash(big.NewInt(1000000000000000000))},
	//enoki-finance 18
	common.HexToAddress("0xa4bad5d040d4464ec5ce130987731f2f428c9307"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pria 18
	common.HexToAddress("0xb9871cb10738eada636432e86fc0cb920dc3de24"): {common.BigToHash(big.NewInt(14080)), common.BigToHash(big.NewInt(1000000000000000000))},
	//neutrino-usd 18
	common.HexToAddress("0x674C6Ad92Fd080e4004b2312b45f796a192D27a0"): {common.BigToHash(big.NewInt(9618)), common.BigToHash(big.NewInt(1000000000000000000))},
	//sergs 18
	common.HexToAddress("0x79BA92DDA26FcE15e1e9af47D5cFdFD2A093E000"): {common.BigToHash(big.NewInt(1810)), common.BigToHash(big.NewInt(1000000000000000000))},
	//csp-dao 18
	common.HexToAddress("0x7f0c8b125040f707441cad9e5ed8a8408673b455"): {common.BigToHash(big.NewInt(91500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//fundamenta 18
	common.HexToAddress("0xaa9d866666c2a3748d6b23ff69e63e52f08d9ab4"): {common.BigToHash(big.NewInt(2822)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yfi-mobi 18
	common.HexToAddress("0x2e2f3246b6c65ccc4239c9ee556ec143a7e5de2c"): {common.BigToHash(big.NewInt(97250)), common.BigToHash(big.NewInt(1000000000000000000))},
	//keep4r 18
	common.HexToAddress("0xa89ac6e529acf391cfbbd377f3ac9d93eae9664e"): {common.BigToHash(big.NewInt(111745)), common.BigToHash(big.NewInt(1000000000000000000))},
	//social-rocket 18
	common.HexToAddress("0x0829d2d5cc09d3d341e813c821b0cfae272d9fb2"): {common.BigToHash(big.NewInt(394)), common.BigToHash(big.NewInt(1000000000000000000))},
	//swiss-finance 18
	common.HexToAddress("0x692eb773e0b5b7a79efac5a015c8b36a2577f65c"): {common.BigToHash(big.NewInt(339073)), common.BigToHash(big.NewInt(1000000000000000000))},
	//liquidefi 18
	common.HexToAddress("0x72ca0501427bb8f089c1c4f767cb17d017e803a9"): {common.BigToHash(big.NewInt(212616)), common.BigToHash(big.NewInt(1000000000000000000))},
	//empty-set-dollar 18
	common.HexToAddress("0x36f3fd68e7325a35eb768f1aedaae9ea0689d723"): {common.BigToHash(big.NewInt(185)), common.BigToHash(big.NewInt(1000000000000000000))},
	//reflect-finance 9
	common.HexToAddress("0xa1afffe3f4d611d252010e3eaf6f4d77088b0cd7"): {common.BigToHash(big.NewInt(327)), common.BigToHash(big.NewInt(1000000000))},
	//tadpole-finance 18
	common.HexToAddress("0x9f7229af0c4b9740e207ea283b9094983f78ba04"): {common.BigToHash(big.NewInt(60199)), common.BigToHash(big.NewInt(1000000000000000000))},
	//komet 18
	common.HexToAddress("0x6cfb6df56bbdb00226aeffcdb2cd1fe8da1abda7"): {common.BigToHash(big.NewInt(295276)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gny 18
	common.HexToAddress("0xb1f871Ae9462F1b2C6826E88A7827e76f86751d4"): {common.BigToHash(big.NewInt(1967)), common.BigToHash(big.NewInt(1000000000000000000))},
	//itchiro-games 18
	common.HexToAddress("0x21cf09BC065082478Dcc9ccB5fd215A978Dc8d86"): {common.BigToHash(big.NewInt(23111)), common.BigToHash(big.NewInt(1000000000000000000))},
	//baepay 4
	common.HexToAddress("0x6bffa07a1b0cebc474ce6833eaf2be6326252449"): {common.BigToHash(big.NewInt(664)), common.BigToHash(big.NewInt(10000))},
	//bifrost 18
	common.HexToAddress("0x0c7D5ae016f806603CB1782bEa29AC69471CAb9c"): {common.BigToHash(big.NewInt(1773)), common.BigToHash(big.NewInt(1000000000000000000))},
	//elysia 18
	common.HexToAddress("0x2781246fe707bb15cee3e5ea354e2154a2877b16"): {common.BigToHash(big.NewInt(92)), common.BigToHash(big.NewInt(1000000000000000000))},
	//prophet 9
	common.HexToAddress("0x8d5db0c1f0681071cb38a382ae6704588d9da587"): {common.BigToHash(big.NewInt(1141)), common.BigToHash(big.NewInt(1000000000))},
	//buy-sell 18
	common.HexToAddress("0xa30189d8255322a2f8b2a77906b000aeb005570c"): {common.BigToHash(big.NewInt(12249)), common.BigToHash(big.NewInt(1000000000000000000))},
	//basis-cash 18
	common.HexToAddress("0x3449FC1Cd036255BA1EB19d65fF4BA2b8903A69a"): {common.BigToHash(big.NewInt(265)), common.BigToHash(big.NewInt(1000000000000000000))},
	//predictz 18
	common.HexToAddress("0x4e085036a1b732cbe4ffb1c12ddfdd87e7c3664d"): {common.BigToHash(big.NewInt(121300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xvix 18
	common.HexToAddress("0x4bAE380B5D762D543d426331b8437926443ae9ec"): {common.BigToHash(big.NewInt(310000)), common.BigToHash(big.NewInt(1000000000000000000))},
	//seth 18
	common.HexToAddress("0x5e74c9036fb86bd7ecdcb084a0673efc32ea31cb"): {common.BigToHash(big.NewInt(32546600)), common.BigToHash(big.NewInt(1000000000000000000))},
	//basis-share 18
	common.HexToAddress("0x106538CC16F938776c7c180186975BCA23875287"): {common.BigToHash(big.NewInt(17419)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mirrored-ishares-gold-trust 18
	common.HexToAddress("0x1d350417d9787E000cc1b95d70E9536DcD91F373"): {common.BigToHash(big.NewInt(352720)), common.BigToHash(big.NewInt(1000000000000000000))},
	//goldenratioperliquidity 18
	common.HexToAddress("0x15e4132dcd932e8990e794d1300011a472819cbd"): {common.BigToHash(big.NewInt(857569)), common.BigToHash(big.NewInt(1000000000000000000))},
	//n3rd-finance 18
	common.HexToAddress("0x32c868f6318d6334b2250f323d914bc2239e4eee"): {common.BigToHash(big.NewInt(195100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unilock-network 18
	common.HexToAddress("0x354e514c135c8603f840ffadb4c33cde6d2a37e0"): {common.BigToHash(big.NewInt(359)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tornado 18
	common.HexToAddress("0x7A3D5d49D64E57DBd6FBB21dF7202bD3EE7A2253"): {common.BigToHash(big.NewInt(709400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bitpower 18
	common.HexToAddress("0x52d904eff2605463c2f0b338d34abc9b7c3e3b08"): {common.BigToHash(big.NewInt(90)), common.BigToHash(big.NewInt(1000000000000000000))},
	//royale-finance 18
	common.HexToAddress("0x7eaf9c89037e4814dc0d9952ac7f888c784548db"): {common.BigToHash(big.NewInt(444)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xdef-finance 9
	common.HexToAddress("0x5166d4ce79b9bf7df477da110c560ce3045aa889"): {common.BigToHash(big.NewInt(4554)), common.BigToHash(big.NewInt(1000000000))},
	//wrapped-monero 18
	common.HexToAddress("0x465e07d6028830124be2e4aa551fbe12805db0f5"): {common.BigToHash(big.NewInt(2328900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//prophecy 18
	common.HexToAddress("0x3C81D482172cC273c3b91dD9D8eb212023D00521"): {common.BigToHash(big.NewInt(31)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defisocial-gaming 18
	common.HexToAddress("0x54ee01beB60E745329E6a8711Ad2D6cb213e38d7"): {common.BigToHash(big.NewInt(2797400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//armor-nxm 18
	common.HexToAddress("0x1337def18c680af1f9f45cbcab6309562975b1dd"): {common.BigToHash(big.NewInt(613100)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yftether 18
	common.HexToAddress("0x94f31ac896c9823d81cf9c2c93feceed4923218f"): {common.BigToHash(big.NewInt(163266)), common.BigToHash(big.NewInt(1000000000000000000))},
	//newscrypto 18
	common.HexToAddress("0x968f6f898a6df937fc1859b323ac2f14643e3fed"): {common.BigToHash(big.NewInt(3620)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xstable-protocol 9
	common.HexToAddress("0x91383a15c391c142b80045d8b4730c1c37ac0378"): {common.BigToHash(big.NewInt(2106)), common.BigToHash(big.NewInt(1000000000))},
	//protocol-finance 18
	common.HexToAddress("0x7b69d465c0f9fb22affae56aa86149973e9b0966"): {common.BigToHash(big.NewInt(132900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//qfinance 18
	common.HexToAddress("0x6fe88a211863d0d818608036880c9a4b0ea86795"): {common.BigToHash(big.NewInt(3247)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yfione 18
	common.HexToAddress("0xac0c8da4a4748d8d821a0973d00b157aa78c473d"): {common.BigToHash(big.NewInt(494900)), common.BigToHash(big.NewInt(1000000000000000000))},
	//lotto 18
	common.HexToAddress("0xb0dFd28d3CF7A5897C694904Ace292539242f858"): {common.BigToHash(big.NewInt(142)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mp3 18
	common.HexToAddress("0x018fb5af9d015af25592a014c4266a84143de7a0"): {common.BigToHash(big.NewInt(156)), common.BigToHash(big.NewInt(1000000000000000000))},
	//interop 18
	common.HexToAddress("0x2eC75589856562646afE393455986CaD26c4Cc5f"): {common.BigToHash(big.NewInt(7645)), common.BigToHash(big.NewInt(1000000000000000000))},
	//name-change-token 18
	common.HexToAddress("0x8a9c4dfe8b9d8962b31e4e16f8321c44d48e246e"): {common.BigToHash(big.NewInt(154)), common.BigToHash(big.NewInt(1000000000000000000))},
	//chow-chow 9
	common.HexToAddress("0x925f2c11b99c1a4c46606898ee91ed3d450cfeda"): {common.BigToHash(big.NewInt(32)), common.BigToHash(big.NewInt(1000000000))},
	//wrapped-cryptokitties 18
	common.HexToAddress("0x09fE5f0236F0Ea5D930197DCE254d77B04128075"): {common.BigToHash(big.NewInt(57213)), common.BigToHash(big.NewInt(1000000000000000000))},
	//soar-fi 9
	common.HexToAddress("0xbae5f2d8a1299e5c4963eaff3312399253f27ccb"): {common.BigToHash(big.NewInt(441)), common.BigToHash(big.NewInt(1000000000))},
	//tama-egg-niftygotchi 18
	common.HexToAddress("0x6e742e29395cf5736c358538f0f1372ab3dfe731"): {common.BigToHash(big.NewInt(591704)), common.BigToHash(big.NewInt(1000000000000000000))},
	//basix 18
	common.HexToAddress("0x23157662a9cb9be32d4d9bd019d9bcbaa040a62b"): {common.BigToHash(big.NewInt(4556)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unidexgas 18
	common.HexToAddress("0xa5959e9412d27041194c3c3bcbe855face2864f7"): {common.BigToHash(big.NewInt(188221)), common.BigToHash(big.NewInt(1000000000000000000))},
	//previse 18
	common.HexToAddress("0xa36e59c08c9f251a6b7a9eb6be6e32fd6157acd0"): {common.BigToHash(big.NewInt(1106)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bt-finance 18
	common.HexToAddress("0x76c5449f4950f6338a393f53cda8b53b0cd3ca3a"): {common.BigToHash(big.NewInt(5946)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dexmex 18
	common.HexToAddress("0x0020d80229877b495d2bf3269a4c13f6f1e1b9d3"): {common.BigToHash(big.NewInt(92)), common.BigToHash(big.NewInt(1000000000000000000))},
	//whaleroom 18
	common.HexToAddress("0x2af72850c504ddd3c1876c66a914caee7ff8a46a"): {common.BigToHash(big.NewInt(39244)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mcdonalds-coin 2
	common.HexToAddress("0x8937041c8c52a78c25aa54051f6a9dada23d42a2"): {common.BigToHash(big.NewInt(25)), common.BigToHash(big.NewInt(100))},
	//rug-proof 18
	common.HexToAddress("0xa0bb0027c28ade4ac628b7f81e7b93ec71b4e020"): {common.BigToHash(big.NewInt(956)), common.BigToHash(big.NewInt(1000000000000000000))},
	//defi-wizard 18
	common.HexToAddress("0x7dee45dff03ec7137979586ca20a2f4917bac9fa"): {common.BigToHash(big.NewInt(6653)), common.BigToHash(big.NewInt(1000000000000000000))},
	//marsan-exchange-token 18
	common.HexToAddress("0x9af5a20aac8d83230ba68542ba29d132d50cbe08"): {common.BigToHash(big.NewInt(245)), common.BigToHash(big.NewInt(1000000000000000000))},
	//vow 18
	common.HexToAddress("0x1BBf25e71EC48B84d773809B4bA55B6F4bE946Fb"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//deor 10
	common.HexToAddress("0x63726dae7c57d25e90ec829ce9a5c745ffd984d3"): {common.BigToHash(big.NewInt(44)), common.BigToHash(big.NewInt(10000000000))},
	//prime-whiterock-company 18
	common.HexToAddress("0xa3d93c0616dbc31fef1e112c7665a4ba4ddbf0be"): {common.BigToHash(big.NewInt(40)), common.BigToHash(big.NewInt(1000000000000000000))},
	//playcent 18
	common.HexToAddress("0x657B83A0336561C8f64389a6f5aDE675C04b0C3b"): {common.BigToHash(big.NewInt(568)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unifund 18
	common.HexToAddress("0x04b5e13000c6e9a3255dc057091f3e3eeee7b0f0"): {common.BigToHash(big.NewInt(60)), common.BigToHash(big.NewInt(1000000000000000000))},
	//next-coin 18
	common.HexToAddress("0x377d552914e7a104bc22b4f3b6268ddc69615be7"): {common.BigToHash(big.NewInt(1256)), common.BigToHash(big.NewInt(1000000000000000000))},
	//transmute-protocol 18
	common.HexToAddress("0xbC81BF5B3173BCCDBE62dba5f5b695522aD63559"): {common.BigToHash(big.NewInt(2847)), common.BigToHash(big.NewInt(1000000000000000000))},
	//agoras-tokens 8
	common.HexToAddress("0x738865301a9b7dd80dc3666dd48cf034ec42bdda"): {common.BigToHash(big.NewInt(8023)), common.BigToHash(big.NewInt(100000000))},
	//keytango 18
	common.HexToAddress("0x182f4c4c97cd1c24e1df8fc4c053e5c47bf53bef"): {common.BigToHash(big.NewInt(605)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shadetech 18
	common.HexToAddress("0x8a8221628361fa25294a83a172dd4f0133207b37"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//exrt-network 8
	common.HexToAddress("0xb20043F149817bff5322F1b928e89aBFC65A9925"): {common.BigToHash(big.NewInt(21)), common.BigToHash(big.NewInt(100000000))},
	//rocket-bunny 9
	common.HexToAddress("0x3ea50b7ef6a7eaf7e966e2cb72b519c16557497c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//cops-finance 18
	common.HexToAddress("0x14dfa5cfaafe89d81d7bf3df4e11eaeda0416618"): {common.BigToHash(big.NewInt(4850123)), common.BigToHash(big.NewInt(1000000000000000000))},
	//quai-dao 18
	common.HexToAddress("0x40821cd074dfecb1524286923bc69315075b5c89"): {common.BigToHash(big.NewInt(252)), common.BigToHash(big.NewInt(1000000000000000000))},
	//farming-bad 18
	common.HexToAddress("0x11003e410ca3fcd220765b3d2f343433a0b2bffd"): {common.BigToHash(big.NewInt(57)), common.BigToHash(big.NewInt(1000000000000000000))},
	//rare-pepe 18
	common.HexToAddress("0x0e9b56d2233ea2b5883861754435f9c51dbca141"): {common.BigToHash(big.NewInt(151)), common.BigToHash(big.NewInt(1000000000000000000))},
	//collective 18
	common.HexToAddress("0x75739d5944534115d7c54ee8c73f186d793bae02"): {common.BigToHash(big.NewInt(5301)), common.BigToHash(big.NewInt(1000000000000000000))},
	//delta-finance 18
	common.HexToAddress("0x9ea3b5b4ec044b70375236a281986106457b20ef"): {common.BigToHash(big.NewInt(28561)), common.BigToHash(big.NewInt(1000000000000000000))},
	//nodeseeds 18
	common.HexToAddress("0x747f564d258612ec5c4e24742c5fd4110bcbe46b"): {common.BigToHash(big.NewInt(474400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//yield-protocol 18
	common.HexToAddress("0xa8B61CfF52564758A204F841E636265bEBC8db9B"): {common.BigToHash(big.NewInt(141)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mu-dank 18
	common.HexToAddress("0x9ea1ae46c15a4164b74463bc26f8aa3b0eea2e6e"): {common.BigToHash(big.NewInt(10)), common.BigToHash(big.NewInt(1000000000000000000))},
	//method-finance 18
	common.HexToAddress("0x84ba4aecfde39d69686a841bab434c32d179a169"): {common.BigToHash(big.NewInt(65)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bta-protocol 18
	common.HexToAddress("0x270371c58d9d775ed73971dd414656107384f235"): {common.BigToHash(big.NewInt(11)), common.BigToHash(big.NewInt(1000000000000000000))},
	//xdefi 18
	common.HexToAddress("0x000000000000d0151e748d25b766e77efe2a6c83"): {common.BigToHash(big.NewInt(346)), common.BigToHash(big.NewInt(1000000000000000000))},
	//b21-invest 18
	common.HexToAddress("0x6faa826af0568d1866fca570da79b318ef114dab"): {common.BigToHash(big.NewInt(429)), common.BigToHash(big.NewInt(1000000000000000000))},
	//artx-trading 18
	common.HexToAddress("0x741b0428efdf4372a8df6fb54b018db5e5ab7710"): {common.BigToHash(big.NewInt(814)), common.BigToHash(big.NewInt(1000000000000000000))},
	//frogdao-dime 18
	common.HexToAddress("0x14cfc7aeaa468e8c789785c39e0b753915aeb426"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shardingdao 18
	common.HexToAddress("0x5845cd0205b5d43af695412a79cf7c1aeddb060f"): {common.BigToHash(big.NewInt(2580)), common.BigToHash(big.NewInt(1000000000000000000))},
	//secure-pad-token 18
	common.HexToAddress("0x10994aa2fb8e6ba5d9fb2bc127ff228c4fe6167f"): {common.BigToHash(big.NewInt(13032)), common.BigToHash(big.NewInt(1000000000000000000))},
	//saren 18
	common.HexToAddress("0xbd4a858139b155219e2c8d10135003fdef720b6b"): {common.BigToHash(big.NewInt(346)), common.BigToHash(big.NewInt(1000000000000000000))},
	//busy 18
	common.HexToAddress("0x5CB3ce6D081fB00d5f6677d196f2d70010EA3f4a"): {common.BigToHash(big.NewInt(149)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dart-insurance 18
	common.HexToAddress("0x5a4623F305A8d7904ED68638AF3B4328678edDBF"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cyclone-protocol 18
	common.HexToAddress("0x8861cff2366c1128fd699b68304ad99a0764ef9a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//impermax 18
	common.HexToAddress("0x7b35ce522cb72e4077baeb96cb923a5529764a00"): {common.BigToHash(big.NewInt(1666)), common.BigToHash(big.NewInt(1000000000000000000))},
	//unitedcrowd 18
	common.HexToAddress("0x6d1dc3928604b00180bb570bdae94b9698d33b79"): {common.BigToHash(big.NewInt(251)), common.BigToHash(big.NewInt(1000000000000000000))},
	//franklin 4
	common.HexToAddress("0x85f6eb2bd5a062f5f8560be93fb7147e16c81472"): {common.BigToHash(big.NewInt(110)), common.BigToHash(big.NewInt(10000))},
	//apehaven 18
	common.HexToAddress("0x14dd7ebe6cb084cb73ef377e115554d47dc9d61e"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000000000000))},
	//peri-finance 18
	common.HexToAddress("0x5d30aD9C6374Bf925D0A75454fa327AACf778492"): {common.BigToHash(big.NewInt(5496)), common.BigToHash(big.NewInt(1000000000000000000))},
	//teslafan 18
	common.HexToAddress("0x2d5bed63b0fe325ed3b865ae2cdaa3649eb25461"): {common.BigToHash(big.NewInt(332)), common.BigToHash(big.NewInt(1000000000000000000))},
	//island-coin 9
	common.HexToAddress("0x1681bcB589b3cFCF0c0616B0cE9b19b240643dc1"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//burnx20 9
	common.HexToAddress("0x1e950AF2F6f8505c09F0Ca42c4b38F10979cb22E"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//dick 18
	common.HexToAddress("0x20af547291dfe691baf43658f2c8515076d18408"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//vision-network 18
	common.HexToAddress("0x456ae45c0ce901e2e7c99c0718031cec0a7a59ff"): {common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(1000000000000000000))},
	//freela 18
	common.HexToAddress("0x29ceddcf0da3c1d8068a7dfbd0fb06c2e438ff70"): {common.BigToHash(big.NewInt(45)), common.BigToHash(big.NewInt(1000000000000000000))},
	//kombai-inu 9
	common.HexToAddress("0x3fce6ae1f55656663ba6a5b0e0812463cf45c2ee"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//bulk 18
	common.HexToAddress("0xa143ac515dca260a46c742c7251ef3b268639593"): {common.BigToHash(big.NewInt(292)), common.BigToHash(big.NewInt(1000000000000000000))},
	//direwolf 2
	common.HexToAddress("0xbdea5bb640dbfc4593809deec5cdb8f99b704cd2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100))},
	//give-global 18
	common.HexToAddress("0xba8e5a4c64c1be42230910f7b39a6388f3d4297c"): {common.BigToHash(big.NewInt(4)), common.BigToHash(big.NewInt(1000000000000000000))},
	//jomon-inu 9
	common.HexToAddress("0x439dd02bFd144A5d6A5967895358E0d25d5ab784"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//tinku 9
	common.HexToAddress("0x47FA4B26c1c52Bc35654F98D10Cd61b9f3E10267"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//cryption-network 18
	common.HexToAddress("0x429876c4a6f89fb470e92456b8313879df98b63c"): {common.BigToHash(big.NewInt(371)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cavapoo 9
	common.HexToAddress("0x456d8f0d25a4e787ee60c401f8b963a465148f70"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//star-foxx 18
	common.HexToAddress("0x31D457E7bcFf5Bc9A5Ef86E6a5eA1DB5b5C3BFB0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bella-protocol 18
	common.HexToAddress("0xa91ac63d040deb1b7a5e4d4134ad23eb0ba07e14"): {common.BigToHash(big.NewInt(13508)), common.BigToHash(big.NewInt(1000000000000000000))},
	//boombaby-io 9
	common.HexToAddress("0x82b89e0f9c0695639eb88659d0c306dbc242af96"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//sakhalin-husky 9
	common.HexToAddress("0x2b1fe2cea92436e8c34b7c215af66aaa2932a8b2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//ofc-coin 9
	common.HexToAddress("0xb3b975fc904e67858ecfee48a49d7269b3e0b949"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//godl 18
	common.HexToAddress("0x7f509465c38b66bdecec2cfdc842e11809cc8357"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tardigrades-finance-eth 9
	common.HexToAddress("0x92a42db88ed0f02c71d439e55962ca7cab0168b5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//dark-matter 18
	common.HexToAddress("0x79126d32a86e6663f3aaac4527732d0701c1ae6c"): {common.BigToHash(big.NewInt(377400)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polkalokr 18
	common.HexToAddress("0x80ce3027a70e0a928d9268994e9b85d03bd4cdcf"): {common.BigToHash(big.NewInt(1054)), common.BigToHash(big.NewInt(1000000000000000000))},
	//digies-coin 9
	common.HexToAddress("0x7333cbf5b0b843b4129e234f791b0058347f671a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//projekt-diamond 9
	common.HexToAddress("0x53109fe9e044f2c324d00ad85bfb0b13ce379480"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//tenshi 9
	common.HexToAddress("0x9358e3a79d428c7708da22a5bd085159f6818d12"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//night-life-crypto 8
	common.HexToAddress("0x1951ab088141e69a3713a351b0d55ba3acda192c"): {common.BigToHash(big.NewInt(8432)), common.BigToHash(big.NewInt(100000000))},
	//taiyo 9
	common.HexToAddress("0x13db9034c9ca6cb739887288fce790544a476f8c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//savebritney 18
	common.HexToAddress("0x606ce698aea1dca5a2627a4583da13a340667f09"): {common.BigToHash(big.NewInt(23)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dinox 18
	common.HexToAddress("0x20a8cec5fffea65be7122bcab2ffe32ed4ebf03a"): {common.BigToHash(big.NewInt(2422)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gambler-shiba 18
	common.HexToAddress("0xb892249939adbf6d7851864ca9a5c7d2d537af97"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//the-tokenized-bitcoin 8
	common.HexToAddress("0x3212b29E33587A00FB1C83346f5dBFA69A458923"): {common.BigToHash(big.NewInt(396160000)), common.BigToHash(big.NewInt(100000000))},
	//robo-token 18
	common.HexToAddress("0x6fc2f1044a3b9bb3e43a43ec8f840843ed753061"): {common.BigToHash(big.NewInt(265)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ethereum-chain-token 9
	common.HexToAddress("0x59d71082d8a5b18ebc6b653ae422ac4383cd2597"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//meteorite-network 9
	common.HexToAddress("0x765baefcb5418fa9f7dddacb1ccc07bd0e890e4e"): {common.BigToHash(big.NewInt(119300)), common.BigToHash(big.NewInt(1000000000))},
	//key 18
	common.HexToAddress("0x4cd988afbad37289baaf53c13e98e2bd46aaea8c"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//smoothy 18
	common.HexToAddress("0xbF776e4FCa664D791C4Ee3A71e2722990E003283"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//antique-zombie-shards 18
	common.HexToAddress("0x78175901e9B04090Bf3B3D3cB7f91CA986fb1aF6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//picaartmoney 0
	common.HexToAddress("0xA7E0719a65128b2f6cDbc86096753Ff7d5962106"): {common.BigToHash(big.NewInt(112)), common.BigToHash(big.NewInt(1))},
	//puppies-network 9
	common.HexToAddress("0x95f49ae439537e50CED0374c1B52C42AA899741C"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//mirrored-facebook 18
	common.HexToAddress("0x0e99cC0535BB6251F6679Fa6E65d6d3b430e840B"): {common.BigToHash(big.NewInt(3494980)), common.BigToHash(big.NewInt(1000000000000000000))},
	//global-defi 18
	common.HexToAddress("0xb5e88b229b18e748e3aa16a1c2bfefdfc8a5560d"): {common.BigToHash(big.NewInt(15300)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polylauncher 18
	common.HexToAddress("0x6c7b97c7e09e790d161769a52f155125fac6d5a1"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//aelf 18
	common.HexToAddress("0xbf2179859fc6D5BEE9Bf9158632Dc51678a4100e"): {common.BigToHash(big.NewInt(4051)), common.BigToHash(big.NewInt(1000000000000000000))},
	//afterback 18
	common.HexToAddress("0x0eaca6ec24e461f76c4da385571336f954c9652a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//banketh 18
	common.HexToAddress("0xbe0c826f17680d8da620855be89dd6544c034ca1"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//zin-finance 18
	common.HexToAddress("0x033e223870f766644f7f7a4B7dc2E91573707d06"): {common.BigToHash(big.NewInt(8)), common.BigToHash(big.NewInt(1000000000000000000))},
	//snap-token 9
	common.HexToAddress("0x4c5813b8c6fbbac76caa148aaf8910f236b56fdf"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//adventure-token 18
	common.HexToAddress("0xa2ef2757d2ed560c9e3758d1946d7bcccbd5a7fe"): {common.BigToHash(big.NewInt(429)), common.BigToHash(big.NewInt(1000000000000000000))},
	//wrapped-fct 8
	common.HexToAddress("0x415acc3c6636211e67e248dc28400b452acefa68"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(100000000))},
	//polkaparty 18
	common.HexToAddress("0x48592de8cded16f6bb56c896fe1affc37630889c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//flurry 18
	common.HexToAddress("0x60f63b76e2fc1649e57a3489162732a90acf59fe"): {common.BigToHash(big.NewInt(11)), common.BigToHash(big.NewInt(1000000000000000000))},
	//whalestreet-shrimp-token 18
	common.HexToAddress("0x9077f9e1efe0ea72867ac89046b2a6264cbcaef5"): {common.BigToHash(big.NewInt(266)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ledgity 18
	common.HexToAddress("0x85Ffb35957203dfD12061eAeCD708dB623Bd567C"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//contribute-dao 18
	common.HexToAddress("0x8e84ee8b28ddbe2b1d5e204e674460835d298815"): {common.BigToHash(big.NewInt(1083311)), common.BigToHash(big.NewInt(1000000000000000000))},
	//identity 18
	common.HexToAddress("0x6fB1E018f107d3352506c23777e4cd62e063584a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//carboneco 9
	common.HexToAddress("0xbb3c2a170fbb8988cdb41c04344f9863b0f71c20"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//bscstarter 18
	common.HexToAddress("0x1d7Ca62F6Af49ec66f6680b8606E634E55Ef22C1"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tenup 18
	common.HexToAddress("0x7714f320Adca62B149df2579361AfEC729c5FE6A"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bond-appetite-usd 18
	common.HexToAddress("0x9a1997c130f4b2997166975d9aff92797d5134c2"): {common.BigToHash(big.NewInt(9810)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bondappetit-governance-token 18
	common.HexToAddress("0x28A06c02287e657ec3F8e151A13C36A1D43814b0"): {common.BigToHash(big.NewInt(810)), common.BigToHash(big.NewInt(1000000000000000000))},
	//despace-protocol 18
	common.HexToAddress("0x634239cfa331df0291653139d1a6083b9cf705e3"): {common.BigToHash(big.NewInt(1266)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dds-store 9
	common.HexToAddress("0x25e4579f028e2629ed15c70a378d82209cfb5e7d"): {common.BigToHash(big.NewInt(9188)), common.BigToHash(big.NewInt(1000000000))},
	//matrixetf 18
	common.HexToAddress("0x1a57367c6194199e5d9aea1ce027431682dfb411"): {common.BigToHash(big.NewInt(199)), common.BigToHash(big.NewInt(1000000000000000000))},
	//pasv 6
	common.HexToAddress("0x1cea6313400ddbcb503c23f5a4facd3014f29872"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000))},
	//ethereum-pro-new 18
	common.HexToAddress("0xAB6E163cBEB3959b68b90beC722F5a9EEf82bA72"): {common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dfbtc 18
	common.HexToAddress("0x060924fb947e37eee230d0b1a71d9618aec269fc"): {common.BigToHash(big.NewInt(6808)), common.BigToHash(big.NewInt(1000000000000000000))},
	//picipo 18
	common.HexToAddress("0x1e05f68B29b286FB3BbAd3c688D7e2ABda549b80"): {common.BigToHash(big.NewInt(366)), common.BigToHash(big.NewInt(1000000000000000000))},
	//centurion-inu 9
	common.HexToAddress("0x9f91d9f9070b0478abb5a9918c79b5dd533f672c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//two-two 18
	common.HexToAddress("0x41045282901E90BDa7578D628e479E5421D1cDD5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//crypto-phoenix 18
	common.HexToAddress("0x8689d850cdf3b74a1f6a5eb60302c785b71c2fc7"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//beach-token 9
	common.HexToAddress("0xbd15c4c8cd28a08e43846e3155c01a1f648d8d42"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//0xcert 18
	common.HexToAddress("0x83e2be8d114f9661221384b3a50d24b96a5653f5"): {common.BigToHash(big.NewInt(22)), common.BigToHash(big.NewInt(1000000000000000000))},
	//happy-fans 18
	common.HexToAddress("0x3079F61704E9eFa2BcF1db412f735d8d4cFa26f4"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000000000000))},
	//inu-token 9
	common.HexToAddress("0x00f29171d7bcdc464a0758cf3217fe83173772b9"): {common.BigToHash(big.NewInt(39)), common.BigToHash(big.NewInt(1000000000))},
	//haildraconis 18
	common.HexToAddress("0x3b08c03fa8278cf81b9043b228183760376fcdbb"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//internet-of-energy-network 18
	common.HexToAddress("0x1e4E46b7BF03ECE908c88FF7cC4975560010893A"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//protector-roge 9
	common.HexToAddress("0x282d0ad1fa03dfbdb88243b958e77349c73737d1"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//cryptopunt 18
	common.HexToAddress("0x31903E333809897eE57Af57567f4377a1a78756c"): {common.BigToHash(big.NewInt(111)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gogeta-inu 9
	common.HexToAddress("0x636484a1c41e88e3fc7c99248ca0b3c3a844ab86"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//billion-token 18
	common.HexToAddress("0x065cc8636a00c007276ed9cb874cd59b89e6609b"): {common.BigToHash(big.NewInt(4)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ichigo-inu 9
	common.HexToAddress("0x8254c1c134436f74047f79eaaea97e3324ef78b5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//inubis 9
	common.HexToAddress("0xab917b34b57f1c01c5df8ddc0f75828e3914fce6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//charizard-inu 9
	common.HexToAddress("0x727e8260877f8507f8d61917e9778b6af8491e63"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//peanuts 18
	common.HexToAddress("0x9f41da75ab2b8c6f0dcef7173c4bf66bd4f6b36a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mason-token 18
	common.HexToAddress("0x3d2c03b2504e4e593169fac757788aac9d303a4e"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//akamaru-inu 9
	common.HexToAddress("0x4abac7a6acf3ce84f1c2fa07d91e72cdd6081cd3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//eiichiro-oda-inu 9
	common.HexToAddress("0x04dc37b220a055c5f93680815f670babcd912c2c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//jpaw-inu 9
	common.HexToAddress("0x2740641bb774a4f41f814d969ba1967155e3470a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//yukon 9
	common.HexToAddress("0x724a4dbc096e8553120ec99d975ca62c1e4f9f51"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//my-shiba-academia 9
	common.HexToAddress("0x93a20a5f1709659005e1610d1a022d5f1e2d0df7"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//chilliswap 18
	common.HexToAddress("0x12b54baA8FFcFd6679CcF1AE618ca3006cFcc2aC"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cats-claw 9
	common.HexToAddress("0x02eddbbf40f7ab1b6fd1a87bf263d4be967d0552"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//blocks 18
	common.HexToAddress("0x8a6d4c8735371ebaf8874fbd518b56edd66024eb"): {common.BigToHash(big.NewInt(285)), common.BigToHash(big.NewInt(1000000000000000000))},
	//metashib-token 9
	common.HexToAddress("0x181c94a45ed257baf2211d4ff7e1f49a5964134a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//megacosm 9
	common.HexToAddress("0x15fc9f4efdd40f0f8a62f2a2ee7bbc79679540e8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//oobit 18
	common.HexToAddress("0x07f9702ce093db82dfdc92c2c6e578d6ea8d5e22"): {common.BigToHash(big.NewInt(3138)), common.BigToHash(big.NewInt(1000000000000000000))},
	//shokky 9
	common.HexToAddress("0xb02db7bd0cbc93a31f3c92349b4a206368174fc0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//shibamon 9
	common.HexToAddress("0x36b00c4c6ce3653a091c7940fc98c3acb0043871"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//scoobi-doge 18
	common.HexToAddress("0x06a87f6afec4a739c367bef69eefe383d27106bd"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dogus 18
	common.HexToAddress("0x903904cb39bac33d4983ead3b3f573d720c7965e"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//mega-shiba-inu 9
	common.HexToAddress("0x1c23f0f3e06fa0e07c5e661353612a2d63323bc6"): {common.BigToHash(big.NewInt(65)), common.BigToHash(big.NewInt(1000000000))},
	//nezuko-inu 9
	common.HexToAddress("0xbc298dfaa2edda095b924f1390cc38fb7c5f6250"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//berserk-inu 9
	common.HexToAddress("0x55ae8e43172e91fab2a9e97636023f4c87b4c470"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//babelfish 9
	common.HexToAddress("0x014d9a527fe5d11c178d70248921db2b735d6e41"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//mashima-inu 9
	common.HexToAddress("0xb2f8a70b09db0f7795a5f079b5021eb84aa59e28"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//balls 9
	common.HexToAddress("0x174ed6e64a5903b59ca7910081e1e3a2c551afc6"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//momento 9
	common.HexToAddress("0x0ae8b74cd2d566853715800c9927f879d6b76a37"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//togashi-inu 9
	common.HexToAddress("0x5daa0cbe290e082dbfd6f595e2e53b678895f322"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//x-ae-a-12 9
	common.HexToAddress("0x1902882a8f6c7fb1402f83c434ea8e064b35bab3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//rbx 18
	common.HexToAddress("0x8254e26e453eb5abd29b3c37ac9e8da32e5d3299"): {common.BigToHash(big.NewInt(909)), common.BigToHash(big.NewInt(1000000000000000000))},
	//gm-coin 9
	common.HexToAddress("0x73b8726618f53f84eeb860fd50ab217fdf30dea0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//mewtwo-inu 9
	common.HexToAddress("0x4F2AB9D03ce5b8D0d3BcA09259c78005D2775E08"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//mishka-token 9
	common.HexToAddress("0x976091738973b520a514ea206acdd008a09649de"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//first-inu 9
	common.HexToAddress("0x1bdc5e5aa2749b4934c33441e050b8854b77a331"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//entropyfi 18
	common.HexToAddress("0x0a0e3bfD5a8cE610E735D4469Bc1b3b130402267"): {common.BigToHash(big.NewInt(334)), common.BigToHash(big.NewInt(1000000000000000000))},
	//polkainu 9
	common.HexToAddress("0xaabcecd071ab4ace5496f6ff3e1c4c3ee8116f75"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//olympus-inu-dao 9
	common.HexToAddress("0x98F817765f69c802a7b188A3165a3267aD2d1123"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//robin-inu 9
	common.HexToAddress("0x10b6bd5e0abab280ec1c5313ee04ccbe91a2ebae"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//psyduck-inu 9
	common.HexToAddress("0x99342b1a141aa3a02e04afb496562037fdf8e655"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//phantom-protocol 18
	common.HexToAddress("0x3f9bec82c776c47405bcb38070d2395fd18f89d3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//tetsu-inu 9
	common.HexToAddress("0x1e9dae82fa136796d306695b8be1e151bc5365e8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//cross-chain-bridge-token 18
	common.HexToAddress("0x92868a5255c628da08f550a858a802f5351c5223"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//garfield-token 9
	common.HexToAddress("0x7b392dd9bdef6e17c3d1ba62d1a6c7dcc99d839b"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//spidey-inu 9
	common.HexToAddress("0x6ff952aef0c0f7c7e20cc396b798daddf6561f18"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//goldinu 9
	common.HexToAddress("0xb2ed199b46630e789e8740fb83b1611acf018516"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//have-fun-staying-poor 9
	common.HexToAddress("0x7343581f55146951b0f678dc6cfa8fd360e2f353"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//baby-cat-girl 9
	common.HexToAddress("0x06E04bBfA6a53c57EbfC17e1AEed8E2686640eCd"): {common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(1000000000))},
	//consensus-cell-network 2
	common.HexToAddress("0x9b62ec1453cea5dde760aaf662048ca6eeb66e7f"): {common.BigToHash(big.NewInt(80)), common.BigToHash(big.NewInt(100))},
	//no-face-inu 18
	common.HexToAddress("0x3093003005fd7c9c077e85c15ff47bcfcf0397e0"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//naruto-inu 9
	common.HexToAddress("0xbfce0e06dedcbea3e170ba4df2a6793334cac5ef"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//ether-terrestrial 9
	common.HexToAddress("0x316f17a75978575e9fedc839ba393395a9d83877"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//shinedao 18
	common.HexToAddress("0x1c7ede23b1361acc098a1e357c9085d131b34a01"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//axus-coin-project 18
	common.HexToAddress("0x872d63d889d4b445c89a0887dcdbcc179b026432"): {common.BigToHash(big.NewInt(282)), common.BigToHash(big.NewInt(1000000000000000000))},
	//spacelink 9
	common.HexToAddress("0x56a41eef4aba11292c58b39f61dabc82ed22c79b"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//media-eye 18
	common.HexToAddress("0x9a257c90fa239fba07771ef7da2d554d148c2e89"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//ludena-protocol 18
	common.HexToAddress("0xb29663Aa4E2e81e425294193616c1B102B70a158"): {common.BigToHash(big.NewInt(17800)), common.BigToHash(big.NewInt(1000000000000000000))},
	//angle-protocol 18
	common.HexToAddress("0x1a7e4e63778b4f12a199c062f3efdd288afcbce8"): {common.BigToHash(big.NewInt(11500)), common.BigToHash(big.NewInt(1000000000000000000))},
	//zaddy-inu-token 18
	common.HexToAddress("0x4fff29d95a8953ad28847278dd6aa11f4c695a24"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//dinnersready 9
	common.HexToAddress("0x160c280fa54e9e8ee22e4f9a71ec96cc2a40f793"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//junior-shiba 18
	common.HexToAddress("0x73ee71cb9f0276f093f113c94c084a7a58ffd1e9"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//angel-inu 9
	common.HexToAddress("0x2373c5dc96238a64ce4062e74000fd3dacfd3bf7"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//vari-stable-capital 9
	common.HexToAddress("0x99bfe582a97f0ded07ee6fb5c1e5b6f1ff082243"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//dumpbuster 9
	common.HexToAddress("0xa0A9C16856C96D5E9d80a8696eEA5E02B2Dc3398"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//multigencapital 9
	common.HexToAddress("0x3ed5a70a149f3c758231a2d592c5b5b5aee86e35"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//planet-inu 9
	common.HexToAddress("0xa461258c192cb6057ad8729589b0d18b08ccace8"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//gobble-gobble 18
	common.HexToAddress("0x1ec1b3fffd5072d97b27110a667c35025c96d5c5"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//big-brain-capital-dao 9
	common.HexToAddress("0x270719e21852e0e817c4663cc9f1567441d6eaac"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//sportsicon 18
	common.HexToAddress("0x3f68e7b44e9bcb486c2feadb7a2289d9cdfc9088"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//studio-shibli 9
	common.HexToAddress("0xB1A88c33091490218965787919fcc9862C1798eE"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//supermegahyperdoge 9
	common.HexToAddress("0x5644bb2b594fcf6f74384d2ad26c68f02a47981c"): {common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1000000000))},
	//arcane-universe 9
	common.HexToAddress("0x58530a272bf650827ae05fadee76f36271089f7f"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//superbrain-capital-dao 9
	common.HexToAddress("0x2f02bE0C4021022b59E9436f335d69DF95E5222a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//freemoon-eth 9
	common.HexToAddress("0x31f0bc450c12eb62b4c617d4c876f7a66470fcb3"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//cage-io 18
	common.HexToAddress("0x8987a07ba83607a66c7351266e771fb865c9ca6c"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//bxmi-token 18
	common.HexToAddress("0xa0f5505dC06eBE8Ee8CbdC2059eaDE0b9F35cbC2"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//trava-finance 18
	common.HexToAddress("0x186d0ba3dfc3386c464eecd96a61fbb1e2da00bf"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//no-bull 9
	common.HexToAddress("0x20be82943e8d9c682580e11d424ec15db95b4a24"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//green-eyed-monster 9
	common.HexToAddress("0xa22d31228699efffe79b5403da9e7b4009732d6a"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//crafting-finance 18
	common.HexToAddress("0x508df5aa4746be37b5b6a69684dfd8bdc322219d"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000000000000))},
	//cobragoose 9
	common.HexToAddress("0x20dc897a85a204dac089ee1dc1998268a9b17fc1"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//roboshib 9
	common.HexToAddress("0x0b48a744669767a3478293fd4eecb8fdc5d33cda"): {common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1000000000))},
	//governance-ohm 18
	common.HexToAddress("0x0ab87046fBb341D058F17CBC4c1133F25a20a52f"): {common.BigToHash(big.NewInt(164124800)), common.BigToHash(big.NewInt(1000000000000000000))},
}
