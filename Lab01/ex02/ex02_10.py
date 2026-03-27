def dao_nguoc_chuoi (chuoi):
    return chuoi [::-1]
input_string = input(" Mời nhập chuỗi căn đảo ngược: ")
print( "Chuối đảo ngược là:", dao_nguoc_chuoi (input_string))