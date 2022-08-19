# Lessons Learned While Reversing an M32C Firmware


## Info

The TL;DR; of this presentation is about answering the question: how to approach an uncommon embedded architecture and what can be learned from the M32C extensive documentation that might be reusable in a different context (e.g. how to find Interrupt Handlers, figure out what are Special Function Registers, etc.). Various strategies are shared and a few automation techniques with IDAPython are also presented.

I gave this presentation at various conferences (Recon, Summercon and DCHHV) throughout 2022. The latest [version](mc32_lesson_learned.pdf) of the slides was presented at the Hardware Hacking Village during Def Con 30.

This presentation is an offshoot of a research project involving vulnerability research on a BBraun Infusomat pump. See the [original blog](https://www.trellix.com/en-us/about/newsroom/stories/threat-labs/mcafee-enterprise-atr-uncovers-vulnerabilities-in-globally-used-b-braun-infusion-pump.html) for more details. 


## Recordings

Various iterations of the talk were recorded:
- Recon 2022 (shorter ~25 minutes presentation): link pending...
- Summercon 2022 (longer ~50 minutes version): [link](https://youtu.be/0g3xUidRTJc?t=2333)

## Related

See the [original blog](https://www.trellix.com/en-us/about/newsroom/stories/threat-labs/mcafee-enterprise-atr-uncovers-vulnerabilities-in-globally-used-b-braun-infusion-pump.html) for the full story. Recordings of the wider project are also available ([Ekoparty 2021](https://www.youtube.com/watch?v=D0mNc9LK-I4&ab_channel=EkopartySecurityConference) and [Hardwear.io 2021](https://www.youtube.com/watch?v=6agtnfPjd64&ab_channel=hardwear.io)).