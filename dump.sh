cd 'Il2CppDumper-net6-v6.7.46'
eval $(direnv export bash)
wine Il2CppDumper.exe ../game_folder/GameAssembly.dll ../Metadata/global-metadata.dat output
