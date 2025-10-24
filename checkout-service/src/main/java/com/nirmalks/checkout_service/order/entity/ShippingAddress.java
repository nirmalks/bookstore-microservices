package com.nirmalks.checkout_service.order.entity;

import jakarta.persistence.Embeddable;
import jakarta.persistence.Column;

@Embeddable
public class ShippingAddress {

	@Column(name = "shipping_address")
	private String address;

	@Column(name = "shipping_city")
	private String city;

	@Column(name = "shipping_state")
	private String state;

	@Column(name = "shipping_pin_code")
	private String pinCode;

	@Column(name = "shipping_country")
	private String country;

	public ShippingAddress() {
	}

	public ShippingAddress(String address, String city, String state, String pinCode, String country) {
		this.address = address;
		this.city = city;
		this.state = state;
		this.pinCode = pinCode;
		this.country = country;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getPinCode() {
		return pinCode;
	}

	public void setPinCode(String pinCode) {
		this.pinCode = pinCode;
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

}