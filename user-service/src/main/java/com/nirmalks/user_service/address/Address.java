package com.nirmalks.user_service.address;

import com.fasterxml.jackson.annotation.JsonBackReference;

import com.nirmalks.user_service.user.entity.User;
import jakarta.persistence.*;

import java.util.Objects;

@Entity
public class Address {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	Long id;

	String city;

	String state;

	String country;

	String pinCode;

	boolean isDefault;

	String address;

	@ManyToOne
	@JoinColumn(name = "user_id", nullable = false)
	@JsonBackReference
	User user;

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		Address address1 = (Address) o;
		return isDefault == address1.isDefault && Objects.equals(id, address1.id) && Objects.equals(city, address1.city)
				&& Objects.equals(state, address1.state) && Objects.equals(country, address1.country)
				&& Objects.equals(pinCode, address1.pinCode) && Objects.equals(address, address1.address);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id, city, state, country, pinCode, isDefault, address);
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getCity() {
		return city;
	}

	public void setCity(String city) {
		this.city = city;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(String country) {
		this.country = country;
	}

	public String getPinCode() {
		return pinCode;
	}

	public void setPinCode(String pinCode) {
		this.pinCode = pinCode;
	}

	public boolean isDefault() {
		return isDefault;
	}

	public void setDefault(boolean aDefault) {
		isDefault = aDefault;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

}
