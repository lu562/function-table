/**
 \file 		innerproduct.cpp
 \author 	sreeram.sadasivam@cased.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
 Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of the Inner Product using ABY Framework.
 */

#include "innerproduct.h"
#include "../../../abycore/sharing/sharing.h"
#include <string>
#include <fstream>
#include <vector>
#include <utility> // std::pair
#include <stdexcept> // std::runtime_error
#include <sstream> // std::stringstream
#include <iostream>
#include <unordered_map>



/**
 * helper function to read csv files
 */

std::vector<std::pair<std::string, std::vector<uint64_t>>> read_csv(std::string filename){
    // Reads a CSV file into a vector of <string, vector<int>> pairs where
    // each pair represents <column name, column values>

    // Create a vector of <string, int vector> pairs to store the result
    std::vector<std::pair<std::string, std::vector<uint64_t>>> result;

    // Create an input filestream
    std::ifstream myFile(filename);

    // Make sure the file is open
    if(!myFile.is_open()) throw std::runtime_error("Could not open file");

    // Helper vars
    std::string line, colname;
    uint64_t val;

    // Read the column names
    if(myFile.good())
    {
        // Extract the first line in the file
        std::getline(myFile, line);

        // Create a stringstream from line
        std::stringstream ss(line);

        // Extract each column name
        while(std::getline(ss, colname, ',')){
            
            // Initialize and add <colname, int vector> pairs to result
            result.push_back({colname, std::vector<uint64_t> {}});
        }
    }

    // Read data, line by line
    while(std::getline(myFile, line))
    {
        // Create a stringstream of the current line
        std::stringstream ss(line);
        
        // Keep track of the current column index
        int colIdx = 0;
        
        // Extract each integer
        while(ss >> val){
            
            // Add the current integer to the 'colIdx' column's values vector
            result.at(colIdx).second.push_back(val);
            
            // If the next token is a comma, ignore it and move on
            if(ss.peek() == ',') ss.ignore();
            
            // Increment the column index
            colIdx++;
        }
    }

    // Close file
    myFile.close();

    return result;
}


int32_t test_inner_product_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t numbers, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing) {


	/**
	 * offline phase: loading the function tables
	 */

    int k = 8;
    int l = 8;
    uint64_t result;
    std::string block_1_file_name;
    std::string tables_file_name;
    std::string config_file_name;
    std::string combination_file_name;
    if(role == SERVER) {
        block_1_file_name = "block1_p1_001.csv";
        tables_file_name = "tables_p1_001.csv";
        config_file_name = "config_p1_001.csv";
        combination_file_name = "rectable_p1_001.csv";
    } else { //role == CLIENT
        block_1_file_name = "block1_p2_001.csv";
        tables_file_name = "tables_p2_001.csv";
        config_file_name = "config_p2_001.csv";
        combination_file_name = "rectable_p2_001.csv";
    }

    // read config
    uint64_t r_raw;

    std::vector<std::pair<std::string, std::vector<uint64_t>>> config_csv = read_csv(config_file_name);
    for (std::pair<std::string, std::vector<uint64_t>> i: config_csv) {
        if (i.first.compare("k") == 0) {
            k = i.second[0];
        } else if (i.first.compare("r") == 0) {
            r_raw = i.second[0];
        } else if (i.first.compare("l") == 0) {
            l = i.second[0];
        }
    }


    // read the first block
    std::unordered_map<uint64_t, uint64_t> block_1;
    std::unordered_map<uint64_t, uint64_t> bit_b_list;

	std::vector<std::pair<std::string, std::vector<uint64_t>>> first_block_csv = read_csv(block_1_file_name);
    int block_size = first_block_csv[0].second.size();
    for (int i = 0; i < block_size; i++) {
        block_1[first_block_csv[0].second[i]] = first_block_csv[2].second[i];
        bit_b_list[first_block_csv[0].second[i]] = first_block_csv[1].second[i];
    }
    // read the following blocks
    std::vector<std::unordered_map<uint64_t, uint64_t>> blocks_with_bit_0(k - 1);
    std::vector<std::unordered_map<uint64_t, uint64_t>> blocks_with_bit_1(k - 1);

    std::vector<std::pair<std::string, std::vector<uint64_t>>> tables_csv = read_csv(tables_file_name);
    int tables_size = tables_csv[0].second.size();
    for (int i = 0; i < tables_size; i++) {
        if (tables_csv[0].second[i] == 0) {
            blocks_with_bit_0[tables_csv[1].second[i] - 1][tables_csv[2].second[i]] = tables_csv[3].second[i];
        } else {
            blocks_with_bit_1[tables_csv[1].second[i] - 1][tables_csv[2].second[i]] = tables_csv[3].second[i];
        }
    }

    // read the combination table
    std::unordered_map<std::string, uint64_t> combination_table;
	std::vector<std::pair<std::string, std::vector<uint64_t>>> combination_csv = read_csv(combination_file_name);
    int table_size = combination_csv[0].second.size();
    for (int i = 0; i < table_size; i++) {
        std::string string_input = std::to_string(combination_csv[0].second[i]);
        if (string_input.size() < 8) {
            std::string prefix_0(8 - string_input.size(), '0');
            string_input = prefix_0 + string_input;
        }
    	combination_table[string_input] = combination_csv[1].second[i];
    }

	std::cout << "\nOffline phase finished " << std::endl;	


	/**
	 Step 1: Create the ABYParty object which defines the basis of all the
	 operations which are happening.	Operations performed are on the
	 basis of the role played by this object.
	 */
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg);
    ABYParty* party_8_bit = new ABYParty(role, address, port, seclvl, (uint32_t)8, nthreads,
            mt_alg);

	/**
	 Step 2: Get to know all the sharing types available in the program.
	 */
	std::vector<Sharing*>& sharings = party->GetSharings();
    std::vector<Sharing*>& sharings_8_bit = party_8_bit->GetSharings();

	/**
	 Step 3: Create the circuit object on the basis of the sharing type
	 being inputed.
	 */
	ArithmeticCircuit* circ =
			(ArithmeticCircuit*) sharings[sharing]->GetCircuitBuildRoutine();
    ArithmeticCircuit* circ_8_bit =
            (ArithmeticCircuit*) sharings_8_bit[sharing]->GetCircuitBuildRoutine();

	/**
	 * first round.
	 * Naming: secret sharings are prefixed with s_, opened values are prefixed with p_
	 */
	share *s_x_input, *s_r_offline, *s_x_plus_r, *p_x_plus_r;
    // ((uint64_t)1 << 62) - 1
	uint64_t x = ((uint64_t)1 << 62) + 1, x_plus_r;
    uint64_t * block_results = new uint64_t[k];

	s_r_offline = circ->PutSharedINGate(r_raw, bitlen);
	s_x_input = circ->PutSharedINGate(x, bitlen);
	s_x_plus_r = circ->PutADDGate(s_r_offline, s_x_input);
	p_x_plus_r = circ->PutOUTGate(s_x_plus_r, ALL);
	party->ExecCircuit();
	x_plus_r = p_x_plus_r->get_clear_value<uint64_t>();
	std::cout << "\nFirst round finished " << std::endl;
	std::cout << "\nX+R opened: " << x_plus_r << std::endl;
	party->Reset();

	/**
	 * Second round
	 */

    // look up first block table and bit b table
    uint64_t first_piece = x_plus_r >> ((k - 1) * l);
    share *s_b, *p_b;
    uint64_t b = bit_b_list[first_piece];
    block_results[0] = block_1[first_piece];

    s_b = circ_8_bit->PutSharedINGate(b, (uint32_t)8);

    p_b = circ_8_bit->PutOUTGate(s_b, ALL);
    party_8_bit->ExecCircuit();
    b = p_b->get_clear_value<uint64_t>();
    std::cout << "\nSecond round finished " << std::endl;
    std::cout << "\nselection bit opened: " << b << std::endl;
    party_8_bit->Reset();

	/**
	 * third round
	 */

	// look up tables to get all the block results

	uint32_t out_bitlen , out_nvals;
    uint64_t *out_vals;
    share *s_block_results, *p_block_results;

    for (int i = 1; i < k; i++) {
        uint64_t piece = (x_plus_r << (i * l)) >> ((k - 1) * l); 
        if (b == 0) {
            block_results[i] = blocks_with_bit_0[i - 1][piece];
        } else {
            block_results[i] = blocks_with_bit_1[i - 1][piece];            
        }
    }

	s_block_results = circ_8_bit->PutSharedSIMDINGate(k, block_results, (uint32_t)8);

	// open block results.
	p_block_results = circ_8_bit->PutOUTGate(s_block_results, ALL);
	party_8_bit->ExecCircuit();
	p_block_results->get_clear_value_vec(&out_vals, &out_bitlen, &out_nvals) ;
    party_8_bit->Reset();

    // check the combination table to get final results.
    std::string combination_entry = std::to_string(out_vals[0]);
    for (int i = 1; i < k; i++) {       
        combination_entry = combination_entry + std::to_string(out_vals[i]);
    } 
    result = combination_table[combination_entry];
    std::cout << "\nThird round finished " << std::endl;
    
    // // try to open it to check the result
    // share *s_result, *p_result;
    // s_result = circ->PutSharedINGate(result, bitlen);
    // p_result = circ->PutOUTGate(s_result, ALL);
    // party->ExecCircuit();
    // uint64_t result_open;
    // result_open = p_result->get_clear_value<uint64_t>();
    // std::cout << "\n(For verification) Opened final result " << result_open << std::endl;
    // party->Reset();

	delete s_x_input;
	delete s_r_offline;
	delete s_x_plus_r;
	delete p_x_plus_r;
	delete s_b;
	delete p_b;
	delete s_block_results;
	delete p_block_results;
    delete out_vals;
    delete block_results;
    // delete s_result;
    // delete p_result;
	delete party;
    delete party_8_bit;

	return 0;
}

