package com.nirmalks.user_service.address.repository;

import com.nirmalks.user_service.address.Address;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AddressRepository extends JpaRepository<Address, Long> {

}
