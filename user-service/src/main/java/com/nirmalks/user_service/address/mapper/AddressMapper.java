package com.nirmalks.user_service.address.mapper;

import com.nirmalks.user_service.address.Address;
import dto.AddressDto;
import dto.AddressRequestWithUserId;

public class AddressMapper {

	public static Address toEntity(AddressRequestWithUserId request) {
		Address address = new Address();
		address.setCity(request.getCity());
		address.setState(request.getState());
		address.setCountry(request.getCountry());
		address.setPinCode(request.getPinCode());
		address.setDefault(request.isDefault());
		address.setAddress(request.getAddress());
		return address;
	}

	public static AddressDto toDto(Address address) {
		AddressDto dto = new AddressDto();
		dto.setId(address.getId());
		dto.setCity(address.getCity());
		dto.setCountry(address.getCountry());
		dto.setAddress(address.getAddress());
		dto.setPinCode(address.getPinCode());
		dto.setState(address.getState());
		dto.setDefault(address.isDefault());
		return dto;
	}

}
