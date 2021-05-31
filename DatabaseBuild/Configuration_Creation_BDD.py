import mariadb

connect = mariadb.connect(host="localhost", user="root", password="")

print(connect)

#Creation du curseur de la BDD pour effectuer les operations

curseur = connect.cursor()

#Creation de la BDD

curseur.execute("CREATE DATABASE IF NOT EXISTS voting_system;")

#Creation des tables
curseur.execute("USE voting_system;")
curseur.execute("CREATE TABLE IF NOT EXISTS `Candidates` ( `ID_Candidates` VARCHAR(9) PRIMARY KEY NOT NULL, `First Name` VARCHAR(20), `Name` VARCHAR(20), `Electoral_part` VARCHAR(40), `Age` INT ); ")
curseur.execute("CREATE TABLE IF NOT EXISTS `Voter` ( `ID_Voter` VARCHAR(20) PRIMARY KEY NOT NULL, `First Name` VARCHAR(20), `Name` VARCHAR(20), `Sexe`VARCHAR(1), `Date_of_birth` DATE, `Right_of_vote` BOOLEAN ); ")
curseur.execute("CREATE TABLE IF NOT EXISTS `Election` (`Number_voters` INT PRIMARY KEY NOT NULL AUTO_INCREMENT, `ID_Candidates` VARCHAR(500),`ID_signature_1` VARCHAR(300), `Id_signature_2` VARCHAR(300), `Date_of_the_vote` DATE);")
curseur.execute("CREATE TABLE IF NOT EXISTS `Keys` (`Key_N` VARCHAR(500), `Key_E` VARCHAR(500),`Key_D` VARCHAR(500));")

#Ajout des candidats par defaut
curseur.execute("USE voting_system;")
curseur.execute("INSERT INTO `candidates` (`ID_Candidates`, `First Name`, `Name`, `Electoral_part`, `Age`) VALUES('EMMAMACR', 'EMMANUEL', 'MACRON', 'La Republique en Marche', 43),('MARILEPE', 'MARINE', 'LE PEN', 'Front National', 52),('BENOHAMO', 'BENOIT', 'HAMON', 'Groupe Socialiste et apparanté', 53),('JEANMELE', 'JEAN-LUC', 'MELENCHON', 'La France Insoumise', 69),('JEANLASS', 'JEAN', 'LASSALLE', 'Libertés et territoires', 66),('FRANFILL', 'FRANCOIS', 'FILLON', 'Les Républicains', 67),('NATHARTH', 'NATHALIE', 'ARTHAUD', 'Lutte Ouvrière', 51),('PHILPOUT', 'PHILIPPE', 'POUTOU', 'Nouveau Parti anticapitaliste', 54),('JACQCHEM', 'JACQUES', 'CHEMINADE', 'Solidarité et progrès', 79),('FRANASSE', 'FRANCOIS', 'ASSELINEAU', 'Union populaire républicaine', 63);")
curseur.execute("INSERT INTO `keys`(`Key_N`, `Key_E`, `Key_D`) VALUES ('a77361de9fdb8ce43a2f73af1f2946f9c0ba7f7b9cbfe52e921574964f7c1ed73418425d524f1c0db3669fb4eefb7083ea9effe3f74d8c7a712602445cb9c045f41d5f8ec9de075636528b910a920c8472a72a4328aa8f54f0a1c94450aafb1b7540b5dd7fffdf6942ad5df64061def187c2b799b418d28456e588292439e399','010001','17ba9308e0305583d5f6f976bc7cb5f1186d9539281a4d58cf1cb93bbfa1c02110e1cb2dbc47379b7d6bb2800a499945284f45c5c13abd0870d64905f4f9e1940d771da4d0532ac2d3a9634006eea66fe8202a62f8d25bb2d7bfd59b5704da3eabab64529320cd051943e7e7415d4c29173809644f9e885b31299674377da481')")


#Fermeture de la connexion
connect.close()