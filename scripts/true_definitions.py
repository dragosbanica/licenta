import xml.etree.ElementTree as ET

# Liste pentru a stoca definitiile cu result="true" si result="false"
true_def = []
false_def = []

def_info =[]



def get_def_info(filename):
	# Incarca fisierul XML
	path="/home/student/licenta/generated_files/"
	report_name_path=path+filename
	tree = ET.parse(report_name_path)
	root = tree.getroot()

	definitions_21=root[2][1]
	definitions_300 =root[3][0][0]

	for definition in definitions_300:
		result=definition.get('result')
		if result == 'true':
			definition_id=definition.get('definition_id')
			true_def.append(definition_id)

	for definition in definitions_21:
		if(definition.get("id") in true_def): 
			ok=0
			id=definition.get("id")
			for x in definition[0]:
				if (x.tag.split('}')[-1]=='title'):
					titlu=x.text
				elif (x.tag.split('}')[-1]=='description' or (x.tag.split('}')[-1]==None)):
					descriere=x.text
					ok=1
				if ok==1:
					def_info.append([id, titlu, descriere])
					ok=0

	return def_info

def main():
	path="/home/student/usn_report.xml"
	get_def_info(path)

	for item in def_info:
        	id, title, description=item
        	print(f"id: {id}")
        	print(f"title: {title}")
        	print(f"description: {description}\n")
if __name__=="__main__":
	main()
