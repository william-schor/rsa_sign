function sign() {
	if (($# < 1)); then
		echo "Usage: [-c <file to check> <public key>, -getBook, -genkey, -setkey <key>, -key <temp key> <in> <out>, -E <public key> <infile> <outfile>, -d <in> <out>, <in> <out>]"
		return 
	fi


	if [ "$1" = "-c" ] 
		then
		if (($# < 3)); then
			echo "Usage: [-c <file to check> <public key>, -getBook, -genkey, -setkey <key>, -key <temp key> <in> <out>, -E <public key> <infile> <outfile>, -d <in> <out>, <in> <out>]"
			return
		fi

		local signature=`tac $2 | head -n 1`

		$HOME/.sign/sign "-c" $2 $signature $3
		return
	fi

	if [ "$1" = "-d" ] 
		then
		if (($# < 3)); then
			echo "Usage: [-c <file to check> <public key>, -getBook, -genkey, -setkey <key>, -key <temp key> <in> <out>, -E <public key> <infile> <outfile>, -d <in> <out>, <in> <out>]"
			return
		fi

		local signature=`tac $2 | head -n 1`
		# -d <file to decrypt> <signature> <outfile>
		$HOME/.sign/sign "-d" $2 $signature $3
		return
	fi

	if [ "$1" = "-setAddrBook" ]
		then
		if (($# < 2)); then
			echo "Usage: [-c <file to check> <public key>, -getBook, -genkey, -setkey <key>, -key <temp key> <in> <out>, -E <public key> <infile> <outfile>, -d <in> <out>, <in> <out>]"
			return 
		fi
		go build -ldflags "-X main.addressBook=`realpath $2`" -o $HOME/.sign/sign $HOME/.sign/sign.go
		return 
	fi

	$HOME/.sign/sign $@
}
