package main

disallowed_tags := ["latest"]

disallowed_images := ["kalilinux/kali-linux-docker"]

deny[msg] {
	input[i].Cmd == "from"
	val := input[i].Value
	tag := split(val[i], ":")[1]
	contains(tag, disallowed_tags[_])

	msg = sprintf("[%s] tag is not allowed", [tag])
}

deny[msg] {
	input[i].Cmd == "from"
	val := input[i].Value
	image := split(val[i], ":")[0]
	contains(image, disallowed_images[_])

	msg = sprintf("[%s] image is not allowed", [image])
}
