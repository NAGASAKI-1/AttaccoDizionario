start=1
end=100

for (( i=start; i<=end; i++ )); do
        while read line
        do
            echo "Record is : $line"
        done 
    
    # Format the number as a 4-digit zero-padded string (e.g., 0001, 0042)
    filename=$(printf "doc_%04d.enc" "$i")
    outfilename=$(printf "doc_%04d.pdf" "$i")

    openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 1000 -nosalt -pass pass:LA_PASSWORD -in $filename -out $outfilename
    
    # Process your file (e.g., file_0001.txt)
    echo "Processing file_${filename}.enc"
done