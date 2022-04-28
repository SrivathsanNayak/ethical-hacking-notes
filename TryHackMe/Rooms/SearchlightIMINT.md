# Searchlight - IMINT - Easy

* This room is about IMINT/GEOINT (image intelligence and geospatial intelligence). The flags in this room will be in the format ```sl{}```.

* There are 5 elements in IMINT to be considered when looking at an image:

  * Context
  * Foreground
  * Background
  * Map markings
  * Trial and error

```markdown
1. What is the name of the street where this image was taken? - sl{Carnaby Street}

This was clearly visible in the task file.
```

* [Dorking](https://osintcurio.us/2019/12/20/google-dorks/), or using Google search queries for OSINT, is useful for gaining more information about clues given in images.

* [Reverse Searching images](https://www.duplichecker.com/reverse-image-search.php) can help in IMINT.

```markdown
1. Which city is the tube station located in? - sl{London}

We get similar pictures on Googling the terms - "public subway" "underground".
Zooming into the picture, we can also spot the term "circus".

Including that in our Google search query gives us the name of the station.

2. Which tube station do these stairs lead to? - sl{Piccadilly Circus}

3. Which year did this station open? - sl{1906}

4. How many platforms are there in this station? - sl{4}
```

```markdown
1. Which building is this photo taken in? - sl{Vancouver International Airport}

On searching for "yvr connects", we get the website for yvr.ca and the name of an airport; these are major clues.

2. Which country is this building located in? - sl{Canada}

3. Which city is this building located in? - sl{Richmond}
```

```markdown
We are given the following clues:

* It is a coffee shop
* It serves the best lunch
* It is located in Scotland

1. Which city is this coffee shop located in? - sl{Blairgowrie}

2. Which street is this coffee shop located in? - sl{Allan Street}

3. What is their phone number? - sl{+447878 839128}

4. What is their email address? - sl{theweecoffeeshop@aol.com}

5. What is the surname of the owners? - sl{Cochrane}
```

```markdown
1. Which restaurant was this picture taken at? - sl{Katz's Deli}

2. What is the name of the Bon Appétit editor that worked 24 hours at this restaurant? - sl{Andrew Knowlton}
```

```markdown
In the given image, we can see elements of a bike and a moose in the sculpture. Googling for terms like 'bike moose sculpture' gives a few images of the statue in the results.

Using those images as a clue, we can refine our search further.

Now we know that it is Oslo, Norway. Refining our search a few more times by using terms such as 'motor deer' and 'art', we get our answers.

Searching for the photographer can be helpful by using terms such as 'oslo', 'photography'.

1. What is the name of this statue? - sl{Rudolph the Chrome Nosed Reindeer}

2. Who took this image? - sl{Kjersti Stensrud}
```

```markdown
Reverse-searching the image gave exact images. From there onwards, it's just Googling.

Using Yandex image search, we can get similar images as well, which have clues in their captions.

1. What is the name of the character that the statue depicts? - sl{Lady Justice}

2. Where is this statue located? - sl{Alexandria, Virginia}

3. What is the name of the building opposite from this statue? - sl{The Westin Alexandria Old Town}
```

* For [reverse-searching videos](https://nixintel.info/osint-tools/using-ffmpeg-to-grab-stills-and-audio-for-osint/), we can use tools such as [FFmpeg](https://ffmpeg.org/) to extract key images and audio, and then reverse-search.

```shell
which ffmpeg
#shows path for ffmpeg

ffmpeg -i task9.mp4 -r 1 img%06d.jpg -hide_banner
#to grab all frames from the video
#-r 1 is for capturing only one frame from one second of video
#img%6d.jpg is for naming protocol of images
#gives us 49 images

ffmpeg -i task9.mp4 -vn taskaudio.mp3
#this extracts the sound from the video
#optional
```

```markdown
From the extracted images, we can reverse-search key images.

Using the multiple clues, we can find out the location.

1. What is the name of the hotel that my friend is staying in? - sl{Novotel Singapore Clarke Quay}
```
