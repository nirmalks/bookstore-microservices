package com.nirmalks.user_service.address.mapper;

import com.nirmalks.user_service.address.Address;
import dto.AddressRequest;

public class AddressMapper {
    public static Address toEntity(AddressRequest request) {
        Address address = new Address();

        address.setCity(request.getCity());
        address.setState(request.getState());
        address.setCountry(request.getCountry());
        address.setPinCode(request.getPinCode());
        address.setDefault(request.isDefault());
        address.setAddress(request.getAddress());

        return address;
    }
}
