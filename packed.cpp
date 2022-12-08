#include "explorer.h"
#include <bitset>

#include <iostream>
#include <fstream>
#include "pe_lib/pe_bliss.h"
#include "pe_lib/entropy.h"

using namespace pe_bliss;

std::string is_packed(std::string path) {
	std::ifstream pe_file(path, std::ios::in | std::ios::binary);
	if (!pe_file)
	{
		return "";
	}

	pe_base image(pe_factory::create_pe(pe_file));
	const section_list sections = image.get_image_sections();

    double entropy = entropy_calculator::calculate_entropy(sections[0]);
	if (entropy > 6.8)
		return "Packed";

	return "Unpacked";
}

void show_entropy(std::string path) {
	std::ifstream pe_file(path, std::ios::in | std::ios::binary);
	if (!pe_file)
	{
		return;
	}

	std::cout << "File entropy: " << entropy_calculator::calculate_entropy(pe_file) << std::endl;
		pe_base image(pe_factory::create_pe(pe_file));

	std::cout << "Sections entropy: " << entropy_calculator::calculate_entropy(image) << std::endl; //Считаем энтропию всех секций

	const section_list sections = image.get_image_sections();
	for (section_list::const_iterator it = sections.begin(); it != sections.end(); ++it)
	{
		if (!(*it).empty())
			std::cout << "Section [" << (*it).get_name() << "] entropy: " << entropy_calculator::calculate_entropy(*it) << std::endl;
	}

	return ;
}
