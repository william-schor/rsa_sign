function sign() {
	if (($# < 1)); then
		echo "Usage: [-c <file to check> <public key>, -getkey, -genkey, -setkey <key>, -key <temp key> <in> <out>, <in> <out>]"
		return 
	fi

	if [ "$1" = "-setkey" ] 
	  then
	  	if (($# < 2)); then
		echo "Usage: [-c <file to check> <public key>, -getkey, -genkey, -setkey <key>, -key <temp key> <in> <out>, <in> <out>]"
		return 
		fi
	  	go build -ldflags "-X main.privateKeyPath=$2" -o $HOME/path/sign $HOME/path/sign.go
	  	return
	fi

	if [ "$1" = "-c" ] 
	  then
	  	if (($# < 3)); then
			echo "Usage: [-c <file to check> <public key>, -getkey, -genkey, -setkey <key>, -key <temp key> <in> <out>, <in> <out>]"
			return
		fi

	  	local signature=`tac $2 | head -n 1`

	  	$HOME/path/sign "-c" $2 $signature $3
	  	return
	fi 

	$HOME/path/sign $@
}
