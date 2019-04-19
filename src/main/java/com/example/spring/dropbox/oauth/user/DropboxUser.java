package com.example.spring.dropbox.oauth.user;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.BeanUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DropboxUser
		implements OAuth2User {

	static class NameInfo {
		@JsonProperty("given_name")
		String givenName;
		@JsonProperty("surname")
		String surname;
		@JsonProperty("familiar_name")
		String familiarName;
		@JsonProperty("display_name")
		String displayName;
		@JsonProperty("abbreviated_name")
		String abbreviatedName;
	}

	// { "disabled": false, "is_teammate": true}

	@JsonProperty("account_id")
	String accountId;

	@JsonProperty("name")
	NameInfo nameInfo;

	@JsonProperty("email")
	String email;

	@JsonProperty("email_verified")
	Boolean emailVerified;

	@JsonProperty("profile_photo_url")
	String profilePhotoUrl;

	@JsonProperty("disabled")
	Boolean disabled;

	@JsonProperty("is_teammate")
	Boolean teammate;

	@JsonAnySetter
	Map<String, Object> extraParameters = new HashMap<>();

	@Override
	@JsonIgnore
	public String getName() {
		return getAccountId();
	}

	@Override
	@JsonIgnore
	public List<GrantedAuthority> getAuthorities() {
		return Arrays.asList(
				new OAuth2UserAuthority("USER", getAttributes()),
				new SimpleGrantedAuthority("USER"));
	}

	@Override
	@JsonIgnore
	public Map<String, Object> getAttributes() {

		Map<String, Object> attributes = new HashMap<>();
		Map<String, Object> name = new HashMap<>();

		BeanUtils.copyProperties(nameInfo, name);
		BeanUtils.copyProperties(this, attributes, "extraParameters", "nameInfo");

		attributes.putAll(extraParameters);
		attributes.put("name", name);

		return attributes;
	}

}
